using System.Collections.Generic;
using Pug.Application.Security;

namespace Authorized.Tests
{
	class DummySecurityManager : ISecurityManager
	{
		public IUser CurrentUser =>
			new User(
				new BasicPrincipalIdentity(
					"TestUser", "Test User", true, string.Empty,
					new Dictionary<string, string>() { }
				), 
				new DummyUserRoleProvider(true),
				null);
	}
}