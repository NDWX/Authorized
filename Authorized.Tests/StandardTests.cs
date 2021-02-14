using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Pug.Application.Security;
using Xunit;
using Xunit.Extensions.Ordering;

namespace Authorized.Tests
{
	public class AdministratorTestContext
	{
		public IAuthorized Authorized { get; }

		public AdministratorTestContext()
		{
			Authorized = new Authorized(new Options() { }, new DefaultIdentifierGenerator(),
										new DummySecurityManager(), new MemoryDataProvider());
		}
	}

	[TestCaseOrderer("Xunit.Extensions.Ordering.TestCaseOrderer", "Xunit.Extensions.Ordering")]
	[SuppressMessage("ReSharper", "HeapView.DelegateAllocation")]
	public class AdministratorTests : IClassFixture<AdministratorTestContext>
	{
		public AdministratorTestContext TestContext { get; }

		public AdministratorTests(AdministratorTestContext testContext)
		{
			TestContext = testContext;
		}

		[Fact]
		[Order(0)]
		public void UserNotGrantedPermissionShouldNotBeAuthorized()
		{
			Assert.Equal(
					Permission.Denied,
					TestContext.Authorized.IsAuthorized(
						new Noun()
							{

								Type = SubjectTypes.User,
								Identifier = "user"
							},
						AdministrativeActions.ManagePermissions,
						new Noun()
							{
								Type = "OBJECT",
								Identifier = "DEFAULT"
							},
						new Dictionary<string, IEnumerable<string>>(),
						string.Empty,
						string.Empty
						)
				);
		}

		[Fact]
		[Order(1)]
		public void UserWithPermissionShouldBeAuthorized()
		{
			Assert.Equal(
					Permission.Allowed,
					TestContext.Authorized.IsAuthorized(
							new Noun()
							{
								Type = SubjectTypes.User,
								Identifier = "administrator"
							},
							AdministrativeActions.ManagePermissions,
							new Noun()
							{
								Type = "OBJECT",
								Identifier = "DEFAULT"
							},
							new Dictionary<string, IEnumerable<string>>(),
							string.Empty,
							string.Empty
						)
				);
		}

		[Fact]
		[Order(2)]
		public void UnknownUserShouldNotBeGrantedPermission()
		{
			Assert.Equal(
					Permission.Denied,
					TestContext.Authorized.IsAuthorized(
							new Noun()
							{
								Type = SubjectTypes.User,
								Identifier = "unknown"
							},
							AdministrativeActions.ManagePermissions,
							new Noun()
							{
								Type = "OBJECT",
								Identifier = "DEFAULT"
							},
							new Dictionary<string, IEnumerable<string>>(),
							string.Empty,
							string.Empty
						)
				);
		}

		[Fact]
		[Order(3)]
		public void UserWithAuthorizedRoleShouldBeAuthorized()
		{
			Assert.Equal(
					Permission.Allowed,
					TestContext.Authorized.IsAuthorized(
							new Noun()
							{
								Type = SubjectTypes.User,
								Identifier = "unknown"
							},
							new []{"USERS"},
							AdministrativeActions.ViewPermissions,
							new Noun()
							{
								Type = "OBJECT",
								Identifier = "DEFAULT"
							},
							new Dictionary<string, IEnumerable<string>>(),
							string.Empty,
							string.Empty
						)
				);
		}

		[Fact]
		[Order(3)]
		public void UserWithUnknownRoleShouldNotBeAuthorized()
		{
			Assert.Equal(
					Permission.Denied,
					TestContext.Authorized.IsAuthorized(
							new Noun()
							{
								Type = SubjectTypes.User,
								Identifier = "user"
							},
							new []{"UNKNOWN"},
							AdministrativeActions.ManagePermissions,
							new Noun()
							{
								Type = "OBJECT",
								Identifier = "DEFAULT"
							},
							new Dictionary<string, IEnumerable<string>>(),
							string.Empty,
							string.Empty
						)
				);
		}
	}
}