using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Pug.Application.Security;

namespace Pug.Authorized.Tests;

internal class DummyUserRoleProvider : IUserRoleProvider
{
	public const string _user = "user", _administrator = "administrator";
	private readonly Dictionary<string, ICollection<string>> _roles = new ();

	public DummyUserRoleProvider()
	{
		_roles.Add(_administrator, new[] {"USERS", "ADMINISTRATORS"});
		_roles.Add(_user, new[] {"USERS", "GROUP1"});
		_roles.Add("USER2", new[] {"USERS", "GROUP2"});
		_roles.Add("poweruser", new[] {"POWERUSERS", "ADMINISTRATORS"});
		_roles.Add("sysadmin", new[] {"SYSADMINS"});
	}

	public bool UserIsInRole(string user, string role)
	{
		return _roles.ContainsKey(user) && _roles[user].Contains(role);
	}

	public async Task<bool> UserIsInRoleAsync( string user, string role )
	{
		throw new System.NotImplementedException();
	}

	public bool UserIsInRoles(string user, ICollection<string> roles)
	{
		return _roles.ContainsKey(user) && _roles[user].Intersect(roles).Count() == roles.Count;
	}

	public async Task<bool> UserIsInRolesAsync( string user, ICollection<string> roles )
	{
		throw new System.NotImplementedException();
	}

	public IEnumerable<string> GetUserRoles(string user, string domain)
	{
		return _roles.ContainsKey(user) ? _roles[user] : new string[0];
	}

	public async Task<IEnumerable<string>> GetUserRolesAsync( string user, string domain )
	{
		throw new System.NotImplementedException();
	}
}