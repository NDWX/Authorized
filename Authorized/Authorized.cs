using System;
using System.Collections.Generic;
using System.Linq;
using System.Transactions;
using Authorized.Data;
using Authorized.Extensions;
using Pug.Application.Data;
using Pug.Application.Security;

namespace Authorized
{
	public class Authorized : IAuthorized
	{
		private readonly ISecurityManager _securityManager;
		private readonly IApplicationData<IAuthorizedDataStore> _dataStoreProvider;
		private readonly Options _options;
		private readonly IdentifierGenerator _identifierGenerator;

		public Authorized(Options options, IdentifierGenerator identifierGenerator, ISecurityManager securityManager,
						IApplicationData<IAuthorizedDataStore> dataStoreProvider)
		{
			_securityManager = securityManager ?? throw new ArgumentNullException(nameof(securityManager));
			_dataStoreProvider = dataStoreProvider ?? throw new ArgumentNullException(nameof(dataStoreProvider));
			_options = options ?? throw new ArgumentNullException(nameof(options));
			_identifierGenerator = identifierGenerator;
		}

		private Permission GetPermission(Noun subject, string action, Noun @object,
										IDictionary<string, string> context, string purpose,
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
												IDictionary<string, string> context, string purpose,
												string domain, IAuthorizedDataStore dataSession)
		{
			Permission permission = GetPermission(subject, action, @object, context, purpose, domain, dataSession);

			if(permission != Permission.None)
				return permission;

			if(@object != null && !string.IsNullOrWhiteSpace(@object.Type))
			{
				if(!string.IsNullOrWhiteSpace(@object.Identifier))
				{
					@object.Identifier = string.Empty;

					permission =
						GetPermission(subject, action, @object, context, purpose, domain, dataSession);

					if(permission != Permission.None)
						return permission;
				}

				permission =
					GetPermission(subject, action, null, context, purpose, domain, dataSession);

				if(permission != Permission.None)
					return permission;

			}

			return Permission.Denied;
		}

		public Permission IsAuthorized(Noun subject, string action, Noun @object, IDictionary<string, string> context,
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
							Permission.Denied)
							return Permission.Denied;

						return Permission.Allowed;
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
										IDictionary<string, string> context,
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
						if(ctx.@this.GetEffectivePermission(ctx.subject, ctx.action, ctx.@object, ctx.context,
															ctx.purpose,
															ctx.domain, dataSession) == Permission.Denied)
							return Permission.Denied;

						foreach(string role in ctx.effectiveRoles)
						{
							if(ctx.@this.GetEffectivePermission(
									new Noun() {Identifier = role, Type = SubjectTypes.Group},
									ctx.action, ctx.@object, ctx.context, ctx.purpose, ctx.domain, dataSession) ==
								Permission.Denied)

								return Permission.Denied;
						}

						return Permission.Allowed;
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
			return _securityManager.CurrentUser.Identity.Identifier == _options.AdministrativeUser ||
					_securityManager.CurrentUser.GetRoles().Contains(_options.AdministratorGroup);
		}

		public IEnumerable<AccessControlEntry> GetAccessControlEntries(Noun subject, string purpose, Noun @object,
																		string domain)
		{
			if(subject != null && string.IsNullOrWhiteSpace(subject.Type))
				throw new ArgumentException(ExceptionMessages.SUBJECT_TYPE_MUST_BE_SPECIFIED, nameof(subject));

			if(@object == null) throw new ArgumentNullException(nameof(@object));
			if(domain == null) throw new ArgumentNullException(nameof(domain));

			Dictionary<string, string> authorizationContext = new Dictionary<string, string>()
			{
				[AdministrativeAccessControlContextKeys.SubjectType] = subject?.Type,
				[AdministrativeAccessControlContextKeys.SubjectIdentifier] = subject?.Identifier,
				[AdministrativeAccessControlContextKeys.ObjectType] = @object.Type,
				[AdministrativeAccessControlContextKeys.ObjectIdentifier] = @object.Identifier,
				[AdministrativeAccessControlContextKeys.Purpose] = purpose,
				[AdministrativeAccessControlContextKeys.Domain] = domain
			};

			Noun authorizationSubject = new Noun()
			{
				Identifier = _securityManager.CurrentUser.Identity.Identifier, Type = SubjectTypes.User
			};

			return _dataStoreProvider.Execute(
					(dataSession, ctx) =>
					{
						bool allowed =
							ctx.@this._options.AdministrativeActionGrantees == AdministrativeActionGrantees.AllUsers ||
							ctx.@this.UserIsAdministrator() ||
							( // subjects are allowed to view their own permissions and caller is 'subject'
								ctx.subject != null &&
								ctx.subject.Type == SubjectTypes.User &&
								ctx.@this._options.AdministrativeActionGrantees ==
								AdministrativeActionGrantees.Subject &&
								!string.IsNullOrEmpty(ctx.subject.Identifier) &&
								ctx.@this._securityManager.CurrentUser.Identity.Identifier == ctx.subject.Identifier
							) ||
							( // Only users with permissions are allowed to view permissions
								ctx.@this._options.AdministrativeActionGrantees ==
								AdministrativeActionGrantees.AllowedUsers &&
								(
									ctx.@this.GetEffectivePermission(
										ctx.authorizationSubject,
										AdministrativeActions.ViewPermissions,
										ctx.@object,
										ctx.authorizationContext,
										ctx.purpose,
										ctx.domain, dataSession) == Permission.Allowed
								)
							);

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

		public void SetAccessControlEntries(AccessControlEntriesModification action, Noun subject, string purpose,
											Noun @object, string domain,
											IEnumerable<AccessControlEntry> entries)
		{
			if(subject != null && string.IsNullOrWhiteSpace(subject.Type))
				throw new ArgumentException(ExceptionMessages.SUBJECT_TYPE_MUST_BE_SPECIFIED, nameof(subject));

			if(@object == null) throw new ArgumentNullException(nameof(@object));
			if(domain == null) throw new ArgumentNullException(nameof(domain));

			Dictionary<string, string> authorizationContext = new Dictionary<string, string>()
			{
				[AdministrativeAccessControlContextKeys.SubjectType] = subject?.Type,
				[AdministrativeAccessControlContextKeys.SubjectIdentifier] = subject?.Identifier,
				[AdministrativeAccessControlContextKeys.ObjectType] = @object.Type,
				[AdministrativeAccessControlContextKeys.ObjectIdentifier] = @object.Identifier,
				[AdministrativeAccessControlContextKeys.Purpose] = purpose,
				[AdministrativeAccessControlContextKeys.Domain] = domain
			};

			Noun authorizationSubject = new Noun()
			{
				Identifier = _securityManager.CurrentUser.Identity.Identifier, Type = SubjectTypes.User
			};

			_dataStoreProvider.Perform(
					(dataSession, ctx) =>
					{
						bool allowed =
							ctx.@this.UserIsAdministrator() ||
							( // users with permissions are allowed to manage permissions
								ctx.@this._options.AdministrativeActionGrantees ==
								AdministrativeActionGrantees.AllowedUsers &&
								(
									ctx.@this.GetEffectivePermission(
										ctx.authorizationSubject,
										AdministrativeActions.ManagePermissions,
										ctx.@object,
										ctx.authorizationContext,
										ctx.purpose,
										ctx.domain,
										dataSession) == Permission.Allowed
								)
							);

						if(!allowed)
						{
							throw new NotAuthorized();
						}

						// todo: set access control entries

						IEnumerable<AccessControlEntry> existingEntries =
							dataSession.GetAccessControlEntries(ctx.subject, null, ctx.@object, ctx.purpose,
																ctx.domain);

						void InsertEntries(IAuthorizedDataStore dataStore, IEnumerable<AccessControlEntry> __entries, string __domain, string __purpose, Noun __object, IdentifierGenerator __idGenerator)
						{
							foreach(var entry in __entries)
							{
								entry.Identifier = __idGenerator.GetNext();

								if(dataStore.AccessControlEntryExists(entry.Identifier))
									throw new Exception("Identifier generator returned duplicated key.");

								dataStore.InsertAccessControlEntry(__domain, __purpose, __object, entry);
							}
						}

						switch(ctx.action)
						{
							case AccessControlEntriesModification.Replace:

								foreach(var entry in existingEntries)
								{
									dataSession.DeleteAccessControlEntry(entry.Identifier);
								}

								InsertEntries(dataSession, ctx.entries, ctx.domain, ctx.purpose, ctx.@object, ctx.@this._identifierGenerator);

								break;

							case AccessControlEntriesModification.Append:

								InsertEntries(dataSession, ctx.entries, ctx.domain, ctx.purpose, ctx.@object, ctx.@this._identifierGenerator);

								break;

							case AccessControlEntriesModification.Remove:

								foreach(var entry in ctx.entries)
								{
									dataSession.DeleteAccessControlEntry(entry.Identifier);
								}

								break;
						}
					},
					new
					{
						@this = this, action, subject, @object, purpose, domain, entries, authorizationContext,
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