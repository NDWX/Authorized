using System.Collections.Generic;
using Pug.Application.Security;

namespace Pug.Authorized.Tests;

internal class DummySessionUserIdentityAccessor : ISessionUserIdentityAccessor
{
	public DummySessionUserIdentityAccessor()
	{
		User = "testuser";
			
	}

	public IPrincipalIdentity GetUserIdentity()
	{
		return new BasicPrincipalIdentity(
				User, "Test User", true, string.Empty,
				new Dictionary<string, string>()
			);
	}
		
	public string User { get; set; }
}