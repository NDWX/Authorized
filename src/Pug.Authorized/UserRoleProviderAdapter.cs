using Pug.Application.Security;

namespace Pug.Authorized;

public class UserRoleProviderAdapter : IPrincipalRoleProvider
{
	private readonly IUserRoleProvider _userRoleProvider;

	public UserRoleProviderAdapter(IUserRoleProvider userRoleProvider)
	{
		_userRoleProvider = userRoleProvider;
	}

	public bool PrincipalIsInRole( string principal, string role )
	{
		return _userRoleProvider.UserIsInRole( principal, role );
	}

	public Task<bool> PrincipalIsInRoleAsync( string principal, string role )
	{
		return _userRoleProvider.UserIsInRoleAsync( principal, role );
	}

	public bool PrincipalIsInRoles( string principal, ICollection<string> roles )
	{
		return _userRoleProvider.UserIsInRoles( principal, roles );
	}

	public  Task<bool> PrincipalIsInRolesAsync( string principal, ICollection<string> roles )
	{
		return _userRoleProvider.UserIsInRolesAsync( principal, roles );
	}

	public IEnumerable<string> GetPrincipalRoles( string principal )
	{
		return _userRoleProvider.GetUserRoles( principal );
	}

	public Task<IEnumerable<string>> GetPrincipalRolesAsync( string principal )
	{
		return _userRoleProvider.GetUserRolesAsync( principal );
	}
}