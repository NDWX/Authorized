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

		public Authorized(Options options, ISecurityManager securityManager, IApplicationData<IAuthorizedDataStore> dataStoreProvider)
		{
			_securityManager = securityManager ?? throw new ArgumentNullException(nameof(securityManager));
			_dataStoreProvider = dataStoreProvider ?? throw new ArgumentNullException(nameof(dataStoreProvider));
			_options = options ?? throw new ArgumentNullException(nameof(options));
		}

		private Permission GetEffectivePermission(Noun subject, string action, Noun @object, IDictionary<string, string> context, string purpose,
												string domain)
		{
			IEnumerable<AccessControlEntry> accessControlEntries = _dataStoreProvider.Execute(
					(dataSession, ctx) =>
					{
						return dataSession.GetAccessControlEntries(ctx.subject, ctx.action, ctx.@object, ctx.purpose,
																	ctx.domain);
					},
					new {subject, action, @object, context, purpose, domain},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);

			if(!(accessControlEntries?.Any() ?? false))
				return Permission.Denied;

			Permission permission = Permission.Denied;

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

				if( permission < accessControlEntry.Permission)
					permission = accessControlEntry.Permission;
			}

			return permission;
		}

		public Permission IsAuthorized(Noun subject, string action, Noun @object, IDictionary<string, string> context,
										string purpose, string domain)
		{
			if(GetEffectivePermission(subject, action, @object, context, purpose, domain) == Permission.Denied)
				return Permission.Denied;

			return Permission.Allowed;
		}

		public Permission IsAuthorized(Noun subject, IEnumerable<string> effectiveRoles, string action, Noun @object,
										IDictionary<string, string> context,
										string purpose, string domain)
		{
			if(GetEffectivePermission(subject, action, @object, context, purpose, domain) == Permission.Denied)
				return Permission.Denied;

			foreach(string role in effectiveRoles)
			{
				if(GetEffectivePermission(new Noun() {Identifier = role, Type = SubjectTypes.Group}, action, @object, context, purpose,
										domain) == Permission.Denied)
					
					return Permission.Denied;
			}

			return Permission.Allowed;
		}

		bool UserIsAdministrator()
		{
			return _securityManager.CurrentUser.Identity.Identifier == _options.AdministrativeUser ||
					_securityManager.CurrentUser.GetRoles().Contains(_options.AdministratorGroup);
		}

		public IEnumerable<AccessControlEntry> GetAccessControlEntries(Noun subject, string purpose, Noun @object,
																		string domain)
		{
			if(subject == null) throw new ArgumentNullException(nameof(subject));
			if(@object == null) throw new ArgumentNullException(nameof(@object));
			if(domain == null) throw new ArgumentNullException(nameof(domain));

			bool allowed =
				_options.ReadOnlyGrantee == ReadOnlyGrantee.AllUsers ||
				UserIsAdministrator() ||
				(subject.Type == SubjectTypes.User && _options.ReadOnlyGrantee == ReadOnlyGrantee.Subject &&
				_securityManager.CurrentUser.Identity.Identifier == subject.Identifier) ||
				(_options.ReadOnlyGrantee == ReadOnlyGrantee.AllowedUsers &&
				GetEffectivePermission(
					new Noun()
					{
						Identifier = _securityManager.CurrentUser.Identity.Identifier, Type = SubjectTypes.User
					},
					AdministrativeActions.ViewPermissions,
					null,
					new Dictionary<string, string>()
					{
						[AdministrativeAccessControlContextKeys.SubjectType] = subject.Type,
						[AdministrativeAccessControlContextKeys.SubjectIdentifier] = subject.Identifier,
						[AdministrativeAccessControlContextKeys.ObjectType] = @object.Type,
						[AdministrativeAccessControlContextKeys.ObjectIdentifier] = @object.Identifier,
						[AdministrativeAccessControlContextKeys.Purpose] = purpose,
						[AdministrativeAccessControlContextKeys.Domain] = domain
					},
					"ADMINISTRATION",
					"_AUTHORIZED_") == Permission.Allowed
				);

			if(!allowed)
			{
				throw new NotAuthorized();
			}

			return _dataStoreProvider.Execute(
					(dataSession, ctx) =>
					{
						return dataSession.GetAccessControlEntries(ctx.subject, string.Empty, ctx.@object, ctx.purpose,
																	ctx.domain);
					},
					new {subject, @object, purpose, domain},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}

		public void SetAccessControlEntries(Noun subject, string purpose, Noun @object, string domain,
											IEnumerable<AccessControlEntry> entries)
		{
			bool allowed = UserIsAdministrator();

			if(allowed)
			{
				
			}
		}
	}
}