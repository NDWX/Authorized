using System.Collections.Generic;
using Pug.Application.Security;

namespace Pug.Authorized.Tests.Mock;

internal class DummySessionUserIdentityAccessor : ISessionUserIdentityAccessor
{
	public DummySessionUserIdentityAccessor()
	{
		User = "testuser";
			
	}

	public IPrincipalIdentity GetPrincipalIdentity()
	{
		return new BasicPrincipalIdentity(
			User, "Test User", true, string.Empty,
			new Dictionary<string, string>()
		);
	}
	
	public IPrincipalIdentity GetUserIdentity()
	{
		return GetPrincipalIdentity();
	}
		
	public string User { get; set; }
}