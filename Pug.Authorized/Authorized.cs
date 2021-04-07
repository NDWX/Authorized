using System;
using System.Collections.Generic;
using System.Linq;
using System.Transactions;
using Pug.Authorized.Data;
using Pug.Authorized.Extensions;
using Pug.Application.Data;
using Pug.Application.Security;

namespace Pug.Authorized
{
	public class Authorized : IAuthorized
	{
		private readonly IApplicationData<IAuthorizedDataStore> _dataStoreProvider;
		private readonly Options _options;
		private readonly IdentifierGenerator _identifierGenerator;
		private readonly ISessionUserIdentityAccessor _sessionUserIdentityAccessor;
		private readonly IUserRoleProvider _userRoleProvider;

		public Authorized(Options options, IdentifierGenerator identifierGenerator, ISessionUserIdentityAccessor sessionUserIdentityAccessor, IUserRoleProvider userRoleProvider,
						IApplicationData<IAuthorizedDataStore> dataStoreProvider)
		{
			_dataStoreProvider = dataStoreProvider ?? throw new ArgumentNullException(nameof(dataStoreProvider));
			_options = options ?? throw new ArgumentNullException(nameof(options));
			_identifierGenerator = identifierGenerator;
			_sessionUserIdentityAccessor = sessionUserIdentityAccessor ?? throw new ArgumentNullException(nameof(sessionUserIdentityAccessor));
			_userRoleProvider = userRoleProvider ?? throw new ArgumentNullException(nameof(userRoleProvider));
		}

		private Permission GetPermission(Noun subject, string action, Noun @object,
										IDictionary<string, IEnumerable<string>> context, string purpose,
										string domain, IAuthorizedDataStore dataStore)
		{
			IEnumerable<AccessControlEntry> accessControlEntries =
				dataStore.GetAccessControlEntries(subject, action, @object, purpose, domain);

			if(!(accessControlEntries?.Any() ?? false))
				return Permission.None;

			Permission permission = Permission.None;

			foreach(AccessControlEntry accessControlEntry in accessControlEntries)
			{
				bool contextMatched = true;

				foreach(AccessControlContextEntry contextEntry in accessControlEntry.Context)
				{
					if(!context.ContainsKey(contextEntry.Key) || !contextEntry.Evaluate(context[contextEntry.Key]))
					{
						contextMatched = false;
						break;
					}
				}

				if(!contextMatched)
					continue;

				if(accessControlEntry.Permission == Permission.Denied)
					return Permission.Denied;

				if(permission < accessControlEntry.Permission)
					permission = accessControlEntry.Permission;
			}

			return permission;
		}

		private Permission GetEffectivePermission(Noun subject, string action, Noun @object,
												IDictionary<string, IEnumerable<string>> context, string purpose,
												string domain, IAuthorizedDataStore dataSession)
		{
			// check authorization for specified parameters
			Permission permission = GetPermission(subject, action, @object, context, purpose, domain, dataSession);

			if(permission != Permission.None)
				return permission;

			if(@object != null && !string.IsNullOrWhiteSpace(@object.Type))
			{
				Noun obj = new Noun()
				{
					Type = @object.Type,
					Identifier = @object.Identifier
				};

				// check authorization for object type
				if(!string.IsNullOrWhiteSpace(obj.Identifier))
				{
					obj.Identifier = string.Empty;

					permission =
						GetPermission(subject, action, obj, context, purpose, domain, dataSession);

					if(permission != Permission.None)
						return permission;
				}

				// check authorization for action
				permission =
					GetPermission(subject, action, null, context, purpose, domain, dataSession);

				if(permission != Permission.None)
					return permission;

			}

			return Permission.None;
		}

		private Permission GetEffectivePermission(Noun subject, IEnumerable<string> effectiveRoles, string action,
												Noun @object, IDictionary<string, IEnumerable<string>> context,
												string purpose, string domain, IAuthorizedDataStore dataSession)
		{
			// check authorization for user
			Permission permission = GetEffectivePermission(subject, action, @object, context,
															purpose,
															domain, dataSession);

			if(permission == Permission.Denied)
				return Permission.Denied;

			Permission effectivePermission = permission;

			// check authorization for each role
			foreach(string role in effectiveRoles)
			{
				permission = GetEffectivePermission(
					new Noun() {Identifier = role, Type = SubjectTypes.Group},
					action, @object, context, purpose, domain, dataSession);

				if(permission == Permission.Denied)
					return Permission.Denied;

				effectivePermission |= permission;
			}

			return effectivePermission;
		}

		public Permission IsAuthorized(Noun subject, string action, Noun @object, IDictionary<string, IEnumerable<string>> context,
										string purpose, string domain)
		{
			if(string.IsNullOrWhiteSpace(subject.Type))
				throw new ArgumentException(ExceptionMessages.SUBJECT_TYPE_MUST_BE_SPECIFIED, nameof(subject));

			if(string.IsNullOrWhiteSpace(subject.Identifier))
				throw new ArgumentException(ExceptionMessages.SUBJECT_IDENTIFIER_MUST_BE_SPECIFIED, nameof(subject));

			if(string.IsNullOrWhiteSpace(action))
				throw new ArgumentException(ExceptionMessages.VALUE_CANNOT_BE_NULL_OR_WHITESPACE, nameof(action));

			if(@object != null)
			{
				if(string.IsNullOrWhiteSpace(@object.Type))
					throw new ArgumentException(ExceptionMessages.OBJECT_TYPE_MUST_BE_SPECIFIED, nameof(subject));

				if(string.IsNullOrWhiteSpace(@object.Identifier))
					throw new ArgumentException(ExceptionMessages.OBJECT_IDENTIFIER_MUST_BE_SPECIFIED, nameof(subject));
			}

			return _dataStoreProvider.Execute(
					(dataSession, ctx) =>
					{
						if(ctx.@this.GetEffectivePermission(ctx.subject, ctx.action, ctx.@object, ctx.context,
															ctx.purpose,
															ctx.domain, dataSession) ==
							Permission.Allowed)
							return Permission.Allowed;

						return Permission.Denied;
					},
					new {@this = this, subject, action, @object, context, purpose, domain},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}

		public Permission IsAuthorized(Noun subject, IEnumerable<string> effectiveRoles, string action, Noun @object,
										IDictionary<string, IEnumerable<string>> context,
										string purpose, string domain)
		{
			if(string.IsNullOrWhiteSpace(subject.Type))
				throw new ArgumentException(ExceptionMessages.SUBJECT_TYPE_MUST_BE_SPECIFIED, nameof(subject));

			if(string.IsNullOrWhiteSpace(subject.Identifier))
				throw new ArgumentException(ExceptionMessages.SUBJECT_IDENTIFIER_MUST_BE_SPECIFIED, nameof(subject));

			if(effectiveRoles == null) throw new ArgumentNullException(nameof(effectiveRoles));

			if(string.IsNullOrWhiteSpace(action))
				throw new ArgumentException(ExceptionMessages.VALUE_CANNOT_BE_NULL_OR_WHITESPACE, nameof(action));

			if(@object != null)
			{
				if(string.IsNullOrWhiteSpace(@object.Type))
					throw new ArgumentException(ExceptionMessages.OBJECT_TYPE_MUST_BE_SPECIFIED, nameof(subject));

				if(string.IsNullOrWhiteSpace(@object.Identifier))
					throw new ArgumentException(ExceptionMessages.OBJECT_IDENTIFIER_MUST_BE_SPECIFIED, nameof(subject));
			}

			return _dataStoreProvider.Execute(
					(dataSession, ctx) =>
					{
						Permission effectivePermission = ctx.@this.GetEffectivePermission(ctx.subject, ctx.effectiveRoles, ctx.action, ctx.@object,
													ctx.context, ctx.purpose, ctx.domain, dataSession);

						if(effectivePermission == Permission.Denied)
							return effectivePermission;
						
						return (effectivePermission & Permission.Allowed) == Permission.Allowed
									? Permission.Allowed
									: Permission.Denied;
					},
					new {@this = this, subject, effectiveRoles, action, @object, context, purpose, domain},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}

		bool UserIsAdministrator()
		{
			IPrincipalIdentity principalIdentity = _sessionUserIdentityAccessor.GetUserIdentity();
			
			return principalIdentity.Identifier == _options.AdministrativeUser ||
					_userRoleProvider.GetUserRoles(principalIdentity.Identifier).Contains(_options.AdministratorGroup);
		}

		public IEnumerable<AccessControlEntry> GetAccessControlEntries(Noun subject, string purpose, Noun @object,
																		string domain)
		{
			if(subject != null && string.IsNullOrWhiteSpace(subject.Type))
				throw new ArgumentException(ExceptionMessages.SUBJECT_TYPE_MUST_BE_SPECIFIED, nameof(subject));

			if(@object == null) throw new ArgumentNullException(nameof(@object));
			if(domain == null) throw new ArgumentNullException(nameof(domain));

			Dictionary<string, IEnumerable<string>> authorizationContext = new Dictionary<string, IEnumerable<string>>()
			{
				[AdministrativeAccessControlContextKeys.SubjectType] = new [] {subject?.Type},
				[AdministrativeAccessControlContextKeys.SubjectIdentifier] = new [] {subject?.Identifier},
				[AdministrativeAccessControlContextKeys.ObjectType] = new [] {@object.Type},
				[AdministrativeAccessControlContextKeys.ObjectIdentifier] = new [] {@object.Identifier},
				[AdministrativeAccessControlContextKeys.Purpose] = new [] {purpose},
				[AdministrativeAccessControlContextKeys.Domain] = new [] {domain}
			};

			Noun authorizationSubject = new Noun()
			{
				Identifier = _sessionUserIdentityAccessor.GetUserIdentity().Identifier, Type = SubjectTypes.User
			};

			return _dataStoreProvider.Execute(
					(dataSession, ctx) =>
					{
						bool allowed = false;

						switch(ctx.@this._options.AdministrativeActionGrantees)
						{
							case AdministrativeActionGrantees.Administrators:
								
								allowed = ctx.@this.UserIsAdministrator();
								
								break;
							
							case AdministrativeActionGrantees.AllowedUsers:

								Permission effectivePermission = ctx.@this.GetEffectivePermission(
									ctx.authorizationSubject,
									ctx.@this._userRoleProvider.GetUserRoles(ctx.authorizationSubject.Identifier),
									AdministrativeActions.ViewPermissions,
									ctx.@object,
									ctx.authorizationContext,
									ctx.purpose,
									ctx.domain,
									dataSession);

								allowed =
									( // users with permissions are allowed to manage permissions
										effectivePermission == Permission.Allowed
									) ||
									(ctx.@this.UserIsAdministrator() && effectivePermission != Permission.Denied);
								
								break;
							
							case AdministrativeActionGrantees.Subject:
								
								allowed = ctx.subject != null &&
									ctx.subject.Type == SubjectTypes.User &&
									!string.IsNullOrEmpty(ctx.subject.Identifier) &&
									ctx.authorizationSubject.Identifier ==
									ctx.subject.Identifier;

								break;
						}
						
						if(!allowed)
						{
							throw new NotAuthorized();
						}

						return dataSession.GetAccessControlEntries(ctx.subject, string.Empty, ctx.@object, ctx.purpose,
																	ctx.domain);
					},
					new {@this = this, subject, @object, purpose, domain, authorizationContext, authorizationSubject},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}

		public void SetAccessControlEntries(string purpose,
											Noun @object, string domain,
											IEnumerable<AccessControlEntry> entries, Noun subject = null)
		{
			if(subject != null)
			{
				if( string.IsNullOrWhiteSpace(subject.Type))
					throw new ArgumentException(ExceptionMessages.SUBJECT_TYPE_MUST_BE_SPECIFIED, nameof(subject));
				
				if( string.IsNullOrWhiteSpace(subject.Identifier))
					throw new ArgumentException(ExceptionMessages.SUBJECT_IDENTIFIER_MUST_BE_SPECIFIED, nameof(subject));

				foreach(AccessControlEntry entry in entries)
				{
					entry.Subject = subject;
				}
			}
			else
			{
				foreach(AccessControlEntry entry in entries)
				{
					if(entry.Subject == null)
					{
						throw new ArgumentException(ExceptionMessages.ACE_SUBJECT_MUST_BE_SPECIFIED, nameof(entries));
					}

					if(string.IsNullOrEmpty(entry.Subject.Type))
						throw new ArgumentException(ExceptionMessages.ACE_SUBJECT_TYPE_MUST_BE_SPECIFIED, nameof(entries));
				
					if( string.IsNullOrWhiteSpace(entry.Subject.Identifier))
						throw new ArgumentException(ExceptionMessages.ACE_SUBJECT_IDENTIFIER_MUST_BE_SPECIFIED, nameof(subject));
				}
			}

			if(@object == null) throw new ArgumentNullException(nameof(@object));
			if(domain == null) throw new ArgumentNullException(nameof(domain));

			Dictionary<string, IEnumerable<string>> authorizationContext = new Dictionary<string, IEnumerable<string>>()
			{
				[AdministrativeAccessControlContextKeys.SubjectType] = new[] {subject?.Type},
				[AdministrativeAccessControlContextKeys.SubjectIdentifier] = new[] {subject?.Identifier},
				[AdministrativeAccessControlContextKeys.ObjectType] = new[] {@object.Type},
				[AdministrativeAccessControlContextKeys.ObjectIdentifier] = new[] {@object.Identifier},
				[AdministrativeAccessControlContextKeys.Purpose] = new[] {purpose},
				[AdministrativeAccessControlContextKeys.Domain] = new[] {domain}
			};

			Noun authorizationSubject = new Noun()
			{
				Identifier = _sessionUserIdentityAccessor.GetUserIdentity().Identifier, Type = SubjectTypes.User
			};

			_dataStoreProvider.Perform(
					(dataSession, ctx) =>
					{
						bool allowed = false;

						switch(ctx.@this._options.AdministrativeActionGrantees)
						{
							case AdministrativeActionGrantees.Administrators:
								
								allowed = ctx.@this.UserIsAdministrator();
								
								break;
							
							case AdministrativeActionGrantees.AllowedUsers:

								Permission effectivePermission = ctx.@this.GetEffectivePermission(
									ctx.authorizationSubject,
									ctx.@this._userRoleProvider.GetUserRoles(ctx.authorizationSubject.Identifier),
									AdministrativeActions.ManagePermissions,
									ctx.@object,
									ctx.authorizationContext,
									ctx.purpose,
									ctx.domain,
									dataSession);

								allowed =
									( // users with permissions are allowed to manage permissions
										effectivePermission == Permission.Allowed
									) ||
									(ctx.@this.UserIsAdministrator() && effectivePermission != Permission.Denied);

								break;
						}
						
						if(!allowed)
							throw new NotAuthorized();

					},
					new
					{
						@this = this, @object, purpose, domain, entries, authorizationContext,
						authorizationSubject
					},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
			
			_dataStoreProvider.Perform(
					(dataSession, ctx) =>
					{
						void InsertEntries(IAuthorizedDataStore dataStore, IEnumerable<AccessControlEntry> __entries,
											string __domain, string __purpose, Noun __object,
											IdentifierGenerator __idGenerator)
						{
							foreach(var entry in __entries)
							{
								entry.Identifier = __idGenerator.GetNext();

								if(dataStore.AccessControlEntryExists(entry.Identifier))
									throw new Exception("Identifier generator returned duplicated key.");

								dataStore.InsertAccessControlEntry(__domain, __purpose, __object, entry);
							}
						}

						dataSession.DeleteAccessControlEntries(ctx.@object, ctx.subject);
						
						InsertEntries(dataSession, ctx.entries, ctx.domain, ctx.purpose, ctx.@object,
									ctx.@this._identifierGenerator);

					},
					new
					{
						@this = this, subject, @object, purpose, domain, entries, authorizationContext,
						authorizationSubject
					},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}
	}
}