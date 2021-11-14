using System.Collections.Generic;
using System.Linq;
using Pug.Application.Security;

namespace Pug.Authorized.Tests
{
	internal class DummyUserRoleProvider : IUserRoleProvider
	{
		private const string _user = "user", _administrator = "administrator";
		private readonly Dictionary<string, ICollection<string>> _roles = new Dictionary<string, ICollection<string>>();

		public DummyUserRoleProvider()
		{
			_roles.Add(_administrator, new[] {"USERS", "ADMINISTRATORS"});
			_roles.Add(_user, new[] {"USERS"});
			_roles.Add("poweruser", new[] {"POWERUSERS", "ADMINISTRATORS"});
			_roles.Add("sysadmin", new[] {"SYSADMINS"});
		}
		
		public bool UserIsInRole(string user, string domain, string role)
		{
			return _roles.ContainsKey(user) && _roles[user].Contains(role);
		}

		public bool UserIsInRoles(string user, string domain, ICollection<string> roles)
		{
			return _roles.ContainsKey(user) && _roles[user].Intersect(roles).Count() == roles.Count();
		}

		public ICollection<string> GetUserRoles(string user, string domain)
		{
			return _roles.ContainsKey(user) ? _roles[user] : new string[0];
		}
	}
}