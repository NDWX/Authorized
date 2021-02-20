using System.Collections.Generic;
using Pug.Application.Security;

namespace Authorized.Tests
{
	class DummySecurityManager : ISecurityManager
	{
		public DummySecurityManager()
		{
			User = "testuser";
		}
		
		public IUser CurrentUser =>
			new User(
				new BasicPrincipalIdentity(
					User, "Test User", true, string.Empty,
					new Dictionary<string, string>() { }
				), 
				new DummyUserRoleProvider(true),
				null);
		
		public string User { get; set; }
	}
}