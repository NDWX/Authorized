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

		public Authorized(Options options, IdentifierGenerator identifierGenerator,
						ISessionUserIdentityAccessor sessionUserIdentityAccessor, IUserRoleProvider userRoleProvider,
						IApplicationData<IAuthorizedDataStore> dataStoreProvider)
		{
			_dataStoreProvider = dataStoreProvider ?? throw new ArgumentNullException(nameof(dataStoreProvider));
			_options = options ?? throw new ArgumentNullException(nameof(options));
			_identifierGenerator = identifierGenerator;
			_sessionUserIdentityAccessor = sessionUserIdentityAccessor ??
											throw new ArgumentNullException(nameof(sessionUserIdentityAccessor));
			_userRoleProvider = userRoleProvider ?? throw new ArgumentNullException(nameof(userRoleProvider));
		}

		private Permissions GetPermission(Noun subject, string action, DomainObject @object,
										IDictionary<string, IEnumerable<string>> context, string purpose,
										IAuthorizedDataStore dataStore)
		{
			// get object access control entries
			IEnumerable<AccessControlEntry> accessControlEntries =
				dataStore.GetAccessControlEntries(subject, action, @object, purpose);

			if(!(accessControlEntries?.Any() ?? false))
				return Permissions.None;

			Permissions permissions = Permissions.None;

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

				if(accessControlEntry.Permissions == Permissions.Denied)
					return Permissions.Denied;

				if(permissions < accessControlEntry.Permissions)
					permissions = accessControlEntry.Permissions;
			}

			return permissions;
		}

		private Permissions GetEffectivePermission(Noun subject, string action, DomainObject @object,
												IDictionary<string, IEnumerable<string>> context, string purpose,
												IAuthorizedDataStore dataSession)
		{
			// check authorization for specified parameters
			Permissions permissions = GetPermission(subject, action, @object, context, purpose, dataSession);

			if(permissions != Permissions.None)
				return permissions;

			// check permission for 'action' against entire object 'type' rather than specific object
			if(@object != null && !string.IsNullOrWhiteSpace(@object.Object.Type))
			{
				DomainObject obj = new DomainObject()
				{
					Object = new Noun()
					{
						Type = @object.Object.Type,
						Identifier = @object.Object.Identifier
					},
					Domain = @object.Domain
				};

				// check authorization for object type
				if(!string.IsNullOrWhiteSpace(obj.Object.Identifier))
				{
					obj.Object.Identifier = string.Empty;

					permissions =
						GetPermission(subject, action, obj, context, purpose, dataSession);

					if(permissions != Permissions.None)
						return permissions;
				}

				// check authorization for action
				permissions =
					GetPermission(subject, action, new DomainObject() {Domain = @object.Domain, Object = null}, context, purpose, dataSession);

				if(permissions != Permissions.None)
					return permissions;

			}

			return Permissions.None;
		}

		private Permissions GetEffectivePermission(IEnumerable<string> roles, string action, DomainObject @object,
													IDictionary<string, IEnumerable<string>> context,
													string purpose, IAuthorizedDataStore dataStore)
		{
			Permissions permissions = Permissions.None;
			
			Permissions effectivePermissions = permissions;

			// check authorization for each role
			foreach(string role in roles)
			{
				permissions = GetEffectivePermission(
					new Noun() {Identifier = role, Type = SubjectTypes.Group},
					action, @object, context, purpose, dataStore);

				if(permissions == Permissions.Denied)
					return Permissions.Denied;

				effectivePermissions |= permissions;
			}

			return effectivePermissions;
		}

		private Permissions GetEffectivePermission(Noun subject, IEnumerable<string> effectiveRoles, string action,
												DomainObject @object, IDictionary<string, IEnumerable<string>> context,
												string purpose, IAuthorizedDataStore dataSession)
		{
			// check authorization for user
			Permissions permissions = GetEffectivePermission(subject, action, @object, context,
															purpose, dataSession);

			if(permissions == Permissions.Denied)
				return Permissions.Denied;

			Permissions effectivePermissions = permissions;

			// Evaluate effective roles authorization
			effectivePermissions |=
				GetEffectivePermission(effectiveRoles, action, @object, context, purpose, dataSession);

			if(effectivePermissions == Permissions.Denied || subject.Type == SubjectTypes.Group || @object.Domain == _options.ManagementDomain)
				return effectivePermissions;

			IEnumerable<string> managementRoles =
				_userRoleProvider.GetUserRoles(subject.Identifier, _options.ManagementDomain);

			if(!managementRoles.Any())
				return effectivePermissions;
			
			effectivePermissions |=
				GetEffectivePermission(managementRoles, action, @object, context, purpose, dataSession);

			return effectivePermissions;
		}

		public Permissions IsAuthorized(Noun subject, string action, DomainObject @object, IDictionary<string, IEnumerable<string>> context,
										string purpose)
		{
			if(string.IsNullOrWhiteSpace(subject.Type))
				throw new ArgumentException(ExceptionMessages.SUBJECT_TYPE_MUST_BE_SPECIFIED, nameof(subject));

			if(string.IsNullOrWhiteSpace(subject.Identifier))
				throw new ArgumentException(ExceptionMessages.SUBJECT_IDENTIFIER_MUST_BE_SPECIFIED, nameof(subject));

			if(string.IsNullOrWhiteSpace(action))
				throw new ArgumentException(ExceptionMessages.VALUE_CANNOT_BE_NULL_OR_WHITESPACE, nameof(action));

			if(@object == null) throw new ArgumentNullException(nameof(@object));
			
			if(@object.Object != null)
			{
				if(string.IsNullOrWhiteSpace(@object.Object.Type))
					throw new ArgumentException(ExceptionMessages.OBJECT_TYPE_MUST_BE_SPECIFIED, nameof(subject));

				if(string.IsNullOrWhiteSpace(@object.Object.Identifier))
					throw new ArgumentException(ExceptionMessages.OBJECT_IDENTIFIER_MUST_BE_SPECIFIED, nameof(subject));
			}

			IEnumerable<string> effectiveRoles = null;

			if(subject.Type != SubjectTypes.Group)
				effectiveRoles = _userRoleProvider.GetUserRoles(subject.Identifier, @object.Domain);

			return _dataStoreProvider.Execute(
					(dataSession, ctx) =>
					{
						if(ctx.@this.GetEffectivePermission(ctx.subject, ctx.effectiveRoles, ctx.action, ctx.@object, ctx.context,
															ctx.purpose, dataSession) ==
							Permissions.Allowed)
							return Permissions.Allowed;

						return Permissions.Denied;
					},
					new {@this = this, subject, action, @object = @object, context, purpose, effectiveRoles},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}

		public Permissions IsAuthorized(Noun subject, IEnumerable<string> effectiveRoles, string action, DomainObject @object,
										IDictionary<string, IEnumerable<string>> context,
										string purpose)
		{
			if(string.IsNullOrWhiteSpace(subject.Type))
				throw new ArgumentException(ExceptionMessages.SUBJECT_TYPE_MUST_BE_SPECIFIED, nameof(subject));

			if(string.IsNullOrWhiteSpace(subject.Identifier))
				throw new ArgumentException(ExceptionMessages.SUBJECT_IDENTIFIER_MUST_BE_SPECIFIED, nameof(subject));

			if(effectiveRoles == null) throw new ArgumentNullException(nameof(effectiveRoles));

			if(string.IsNullOrWhiteSpace(action))
				throw new ArgumentException(ExceptionMessages.VALUE_CANNOT_BE_NULL_OR_WHITESPACE, nameof(action));

			if(@object == null) throw new ArgumentNullException(nameof(@object));
			
			if(@object.Object != null)
			{
				if(string.IsNullOrWhiteSpace(@object.Object.Type))
					throw new ArgumentException(ExceptionMessages.OBJECT_TYPE_MUST_BE_SPECIFIED, nameof(subject));

				if(string.IsNullOrWhiteSpace(@object.Object.Identifier))
					throw new ArgumentException(ExceptionMessages.OBJECT_IDENTIFIER_MUST_BE_SPECIFIED, nameof(subject));
			}

			return _dataStoreProvider.Execute(
					(dataSession, ctx) =>
					{
						Permissions effectivePermissions = ctx.@this.GetEffectivePermission(ctx.subject, ctx.effectiveRoles, ctx.action, 
							ctx.@object, ctx.context, ctx.purpose, dataSession);

						if(effectivePermissions == Permissions.Denied)
							return effectivePermissions;
						
						return (effectivePermissions & Permissions.Allowed) == Permissions.Allowed
									? Permissions.Allowed
									: Permissions.Denied;
					},
					new {@this = this, subject, effectiveRoles, action,
						@object = @object, context, purpose},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}

		private bool UserIsAdministrator()
		{
			IPrincipalIdentity principalIdentity = _sessionUserIdentityAccessor.GetUserIdentity();

			return principalIdentity.Identifier == _options.AdministrativeUser ||
					_userRoleProvider.UserIsInRole(principalIdentity.Identifier,
													_options.AdministratorRole);
		}

		private static void CheckSubjectSpecificationIsComplete(AccessControlEntry entry, string parameterName)
		{
			if(entry.Subject == null)
			{
				throw new ArgumentException(ExceptionMessages.ACE_SUBJECT_MUST_BE_SPECIFIED, parameterName);
			}

			if(string.IsNullOrEmpty(entry.Subject.Type))
				throw new ArgumentException(ExceptionMessages.ACE_SUBJECT_TYPE_MUST_BE_SPECIFIED, parameterName);

			if(string.IsNullOrWhiteSpace(entry.Subject.Identifier))
				throw new ArgumentException(ExceptionMessages.ACE_SUBJECT_IDENTIFIER_MUST_BE_SPECIFIED, parameterName);
		}

		private static void CheckSubjectSpecificationIsComplete(Noun subject, string parameterName)
		{
			if(string.IsNullOrWhiteSpace(subject.Type))
				throw new ArgumentException(ExceptionMessages.SUBJECT_TYPE_MUST_BE_SPECIFIED, parameterName);

			if(string.IsNullOrWhiteSpace(subject.Identifier))
				throw new ArgumentException(ExceptionMessages.SUBJECT_IDENTIFIER_MUST_BE_SPECIFIED, parameterName);
		}

		public IEnumerable<AccessControlEntry> GetAccessControlEntries(Noun subject, string purpose, DomainObject @object)
		{
			if(subject != null && string.IsNullOrWhiteSpace(subject.Type))
				throw new ArgumentException(ExceptionMessages.SUBJECT_TYPE_MUST_BE_SPECIFIED, nameof(subject));

			if(@object == null) throw new ArgumentNullException(nameof(@object));
			if(@object.Object == null) throw new ArgumentNullException($"{nameof(@object)}.{nameof(@object.Object)}");

			Dictionary<string, IEnumerable<string>> authorizationContext = new Dictionary<string, IEnumerable<string>>()
			{
				[AdministrativeAccessControlContextKeys.SubjectType] = new [] {subject?.Type},
				[AdministrativeAccessControlContextKeys.SubjectIdentifier] = new [] {subject?.Identifier},
				[AdministrativeAccessControlContextKeys.ObjectType] = new [] {@object.Object.Type},
				[AdministrativeAccessControlContextKeys.ObjectIdentifier] = new [] {@object.Object.Identifier},
				[AdministrativeAccessControlContextKeys.ObjectDomain] = new [] {@object.Domain},
				[AdministrativeAccessControlContextKeys.Purpose] = new [] {purpose},
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

								Permissions effectivePermissions = ctx.@this.GetEffectivePermission(
									ctx.authorizationSubject,
									ctx.@this._userRoleProvider.GetUserRoles(ctx.authorizationSubject.Identifier, ctx.@object.Domain),
									AdministrativeActions.ViewPermissions,
									ctx.@object,
									ctx.authorizationContext,
									ctx.purpose,
									dataSession);

								allowed =
									( // users with permissions are allowed to manage permissions
										effectivePermissions == Permissions.Allowed
									) ||
									(ctx.@this.UserIsAdministrator() && effectivePermissions != Permissions.Denied);
								
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

						return dataSession.GetAccessControlEntries(ctx.subject, string.Empty, ctx.@object, ctx.purpose);
					},
					new {@this = this, subject, @object = @object, purpose, authorizationContext, authorizationSubject},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}

		public void SetAccessControlEntries(string purpose,
											DomainObject @object,
											IEnumerable<AccessControlEntry> entries, Noun subject = null)
		{
			if(subject != null)
			{
				CheckSubjectSpecificationIsComplete(subject, nameof(subject));

				foreach(AccessControlEntry entry in entries)
				{
					entry.Subject = subject;
				}
			}
			else
			{
				foreach(AccessControlEntry entry in entries)
				{
					CheckSubjectSpecificationIsComplete(entry, nameof(entries));
				}
			}

			if(@object == null) throw new ArgumentNullException(nameof(@object));
			if(@object.Object == null) throw new ArgumentNullException($"{nameof(@object)}.{nameof(@object.Object)}");

			Dictionary<string, IEnumerable<string>> authorizationContext = new Dictionary<string, IEnumerable<string>>()
			{
				[AdministrativeAccessControlContextKeys.SubjectType] = new[] {subject?.Type},
				[AdministrativeAccessControlContextKeys.SubjectIdentifier] = new[] {subject?.Identifier},
				[AdministrativeAccessControlContextKeys.ObjectType] = new[] {@object.Object.Type},
				[AdministrativeAccessControlContextKeys.ObjectIdentifier] = new[] {@object.Object.Identifier},
				[AdministrativeAccessControlContextKeys.ObjectDomain] = new [] {@object.Domain},
				[AdministrativeAccessControlContextKeys.Purpose] = new[] {purpose},
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

								Permissions effectivePermissions = ctx.@this.GetEffectivePermission(
									ctx.authorizationSubject,
									ctx.@this._userRoleProvider.GetUserRoles(ctx.authorizationSubject.Identifier, ctx.@object.Domain),
									AdministrativeActions.ManagePermissions,
									ctx.@object,
									ctx.authorizationContext,
									ctx.purpose,
									dataSession);

								allowed =
									( // users with permissions are allowed to manage permissions
										effectivePermissions == Permissions.Allowed
									) ||
									(ctx.@this.UserIsAdministrator() && effectivePermissions != Permissions.Denied);

								break;
						}
						
						if(!allowed)
							throw new NotAuthorized();

					},
					new
					{
						@this = this,
						@object = @object, purpose, entries, authorizationContext,
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
											string _purpose, DomainObject __object,
											IdentifierGenerator __idGenerator)
						{
							foreach(var entry in __entries)
							{
								entry.Identifier = __idGenerator.GetNext();

								if(dataStore.AccessControlEntryExists(entry.Identifier))
									throw new DuplicateIdentifierException("Identifier generator returned duplicated key.");

								dataStore.InsertAccessControlEntry(_purpose, __object, entry);
							}
						}

						dataSession.DeleteAccessControlEntries(ctx.@object, ctx.subject);
						
						InsertEntries(dataSession, ctx.entries, ctx.purpose, ctx.@object,
									ctx.@this._identifierGenerator);

					},
					new
					{
						@this = this, subject,
						@object = @object, purpose, entries, authorizationContext,
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