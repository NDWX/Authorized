using Pug.Application.Security;

namespace Authorized.Tests
{
	public class StandardTestContext
	{
		private ISecurityManager SecurityManager { get; }
		
		
		public IAuthorized Authorized { get; }

		public StandardTestContext()
		{
			SecurityManager = new DummySecurityManager();

			Authorized = new Authorized(
					new Options()
					{
						AdministratorGroup = "ADMINISTRATORS",
						AdministrativeActionGrantees = AdministrativeActionGrantees.AllowedUsers
					},
					new DefaultIdentifierGenerator(),
					SecurityManager,
					new MemoryDataProvider()
				);
		}

		public void SetCurrentUser(string username)
		{
			(SecurityManager as DummySecurityManager).User = username;
		}
	}
}