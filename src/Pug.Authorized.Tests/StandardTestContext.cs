namespace Pug.Authorized.Tests
{
	public class StandardTestContext
	{
		private DummySessionUserIdentityAccessor _dummySessionUserIdentityAccessor;
		public IAuthorized Authorized { get; }

		public StandardTestContext()
		{
			_dummySessionUserIdentityAccessor = new DummySessionUserIdentityAccessor();
			
			Authorized = new Authorized(
				new Options
				{
					ManagementDomain = string.Empty,
					AdministratorRole = "ADMINISTRATORS",
					AdministrativeActionGrantees = AdministrativeActionGrantees.AllowedUsers
				},
				new DefaultIdentifierGenerator(),
				_dummySessionUserIdentityAccessor,
					new DummyUserRoleProvider(),
					new MemoryDataProvider()
				);
		}

		public void SetCurrentUser(string username)
		{
			_dummySessionUserIdentityAccessor.User = username;
		}
	}
}