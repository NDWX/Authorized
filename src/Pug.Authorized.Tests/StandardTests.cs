using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using Pug.Application.Security;
using Xunit;
using Xunit.Extensions.Ordering;

namespace Pug.Authorized.Tests
{
	[TestCaseOrderer("Xunit.Extensions.Ordering.TestCaseOrderer", "Xunit.Extensions.Ordering")]
	[SuppressMessage("ReSharper", "HeapView.DelegateAllocation")]
	public class StandardTests : IClassFixture<StandardTestContext>
	{
		internal StandardTestContext TestContext { get; }

		public StandardTests(StandardTestContext testContext)
		{
			TestContext = testContext;
		}

		[Fact]
		[Order(0)]
		public void UserNotGrantedPermissionShouldNotBeAuthorized()
		{
			Assert.Equal(
					Permissions.Denied,
					TestContext.Authorized.IsAuthorized(
							new Noun
							{
								Type = SubjectTypes.User,
								Identifier = "user"
							},
							AdministrativeActions.ManagePermissions,
							new DomainObject
							{
								Domain = string.Empty,
								Object = new Noun() {
								Type = "OBJECT",
								Identifier = "DEFAULT"
								}
							},
							new Dictionary<string, IEnumerable<string>>(),
							string.Empty
						)
				);
		}

		[Fact]
		public void UserWithPermissionShouldBeAuthorized()
		{
			Assert.Equal(
					Permissions.Allowed,
					TestContext.Authorized.IsAuthorized(
							new Noun
							{
								Type = SubjectTypes.User,
								Identifier = "administrator"
							},
							AdministrativeActions.ManagePermissions,
							new DomainObject
							{
								Domain = string.Empty,
								Object = new Noun() {
								Type = "OBJECT",
								Identifier = "DEFAULT"
								}
							},
							new Dictionary<string, IEnumerable<string>>(),
							string.Empty
						)
				);
		}

		[Fact]
		public void UnknownUserShouldNotBeGrantedPermission()
		{
			Assert.Equal(
					Permissions.Denied,
					TestContext.Authorized.IsAuthorized(
							new Noun
							{
								Type = SubjectTypes.User,
								Identifier = "unknown"
							},
							AdministrativeActions.ManagePermissions,
							new DomainObject
							{
								Domain = string.Empty,
								Object = new Noun() {
								Type = "OBJECT",
								Identifier = "DEFAULT"
								}
							},
							new Dictionary<string, IEnumerable<string>>(),
							string.Empty
						)
				);
		}

		[Fact]
		public void UserWithAuthorizedRoleShouldBeAuthorized()
		{
			Assert.Equal(
					Permissions.Allowed,
					TestContext.Authorized.IsAuthorized(
							new Noun
							{
								Type = SubjectTypes.User,
								Identifier = "unknown"
							},
							new[] {"USERS"},
							AdministrativeActions.ViewPermissions,
							new DomainObject
							{
								Domain = string.Empty,
								Object = new Noun() {
								Type = "OBJECT",
								Identifier = "DEFAULT"
								}
							},
							new Dictionary<string, IEnumerable<string>>(),
							string.Empty
						)
				);
		}

		[Fact]
		public void UserWithUnknownRoleShouldNotBeAuthorized()
		{
			Assert.Equal(
					Permissions.Denied,
					TestContext.Authorized.IsAuthorized(
							new Noun
							{
								Type = SubjectTypes.User,
								Identifier = "user"
							},
							new[] {"UNKNOWN"},
							AdministrativeActions.ManagePermissions,
							new DomainObject
							{
								Domain = string.Empty,
								Object = new Noun() {
								Type = "OBJECT",
								Identifier = "DEFAULT"
								}
							},
							new Dictionary<string, IEnumerable<string>>(),
							string.Empty
						)
				);
		}

		[Fact]
		public void DefaultAdminsitratorGroupUserShouldBeAllowedToManagePermissions()
		{
			TestContext.SetCurrentUser("administrator");

			TestContext.Authorized.SetAccessControlEntries(
					string.Empty,
					new DomainObject
					{
						Domain = string.Empty,
						Object = new Noun() {
							Type = "OBJECT",
							Identifier = "DEFAULT"
						}
					},
					new[]
					{
						new AccessControlEntry
						{
							Action = "VIEW",
							Permissions = Permissions.Allowed,
							Subject = new Noun
							{
								Type = SubjectTypes.User,
								Identifier = "user"
							}
						}
					}
				);
		}

		[Fact]
		public void MembersOfPermittedGroupShouldBeAllowedToManagePermissions()
		{
			TestContext.SetCurrentUser("sysadmin");

			TestContext.Authorized.SetAccessControlEntries(
					string.Empty,
					new DomainObject
					{
						Domain = string.Empty,
						Object = new Noun() {
						Type = "OBJECT",
						Identifier = "DEFAULT"
						}
						},
					new[]
					{
						new AccessControlEntry
						{
							Action = "VIEW",
							Permissions = Permissions.Allowed,
							Subject = new Noun
							{
								Type = SubjectTypes.User,
								Identifier = "user"
							},
							Context = new AccessControlContextEntry[] { }
						}
					}
				);
		}

		[Fact]
		public void MembersOfRestrictedGroupShouldNotBeAllowedToManagePermissions()
		{
			TestContext.SetCurrentUser("poweruser");

			Assert.Throws<NotAuthorized>(() =>
					{
						TestContext.Authorized.SetAccessControlEntries(
								string.Empty,
								new DomainObject
								{
									Domain = string.Empty,
									Object = new Noun()
									{
										Type = "OBJECT",
										Identifier = "DEFAULT"
									}
								},
								new[]
								{
									new AccessControlEntry
									{
										Action = "VIEW",
										Permissions = Permissions.Allowed,
										Subject = new Noun
										{
											Type = SubjectTypes.User,
											Identifier = "user"
										}
									}
								}
							);
					}
				);
		}
	}
}