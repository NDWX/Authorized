using System;
using System.Collections.Generic;
using System.Security.Principal;
using System.Threading.Tasks;
using Pug.Application.Security;

namespace Pug.Authorized.Tests.Mock;

public class User : IUser
{
		private readonly IPrincipalRoleProvider _userRoleProvider;
		private readonly IAuthorizationProvider _authorizationProvider;

		public User(IPrincipalIdentity credentials, IPrincipalRoleProvider userRoleProvider,
					IAuthorizationProvider authorizationProvider)
		{
			Identity = credentials;
			_userRoleProvider = userRoleProvider;
			_authorizationProvider = authorizationProvider;
		}

		public bool IsInRole(string role)
		{
			return _userRoleProvider.PrincipalIsInRole(Identity.Identifier, role);
		}

		public bool IsAuthorized(IDictionary<string, string> context, string operation, DomainObject resource, string purpose = "")
		{
			return _authorizationProvider.UserIsAuthorized(context, this, operation, resource, purpose);
		}


		public bool IsAuthorized( IDictionary<string, string> context, string operation, NounQualifier resource, string purpose = "" )
		{
			return _authorizationProvider.PrincipalIsAuthorized(context, this, operation, resource, purpose);
		}

		public Task<bool> IsAuthorizedAsync( IDictionary<string, string> context, string operation, DomainObject resource, string purpose = "" )
		{
			return _authorizationProvider.UserIsAuthorizedAsync(context, this, operation, resource, purpose);
		}

		public async Task<bool> IsAuthorizedAsync( IDictionary<string, string> context, string operation, NounQualifier resource, string purpose = "" )
		{
			return await _authorizationProvider.PrincipalIsAuthorizedAsync(context, this, operation, resource, purpose);
		}

		public IEnumerable<string> GetRoles()
		{
			return _userRoleProvider.GetPrincipalRoles(Identity.Identifier);
		}

		public Task<IEnumerable<string>> GetRolesAsync( )
		{
			return _userRoleProvider.GetPrincipalRolesAsync(Identity.Identifier);
		}

		public IPrincipalIdentity Identity { get; }

		IIdentity System.Security.Principal.IPrincipal.Identity => Identity;

		private void ReleaseUnmanagedResources()
		{
			Identity.Dispose();
		}

		protected virtual void Dispose( bool disposing )
		{
			ReleaseUnmanagedResources();
			
			if( disposing )
			{
				Identity?.Dispose();
			}
		}

		public void Dispose()
		{
			Dispose( true );
			GC.SuppressFinalize( this );
		}

		~User()
		{
			Dispose( false );
		}
}