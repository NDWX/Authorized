namespace Authorized.Tests
{
	public class StandardTestContext
	{
		public IAuthorized Authorized { get; }

		public StandardTestContext()
		{
			Authorized = new Authorized(new Options() { }, new DefaultIdentifierGenerator(),
										new DummySecurityManager(), new MemoryDataProvider());
		}
	}
}