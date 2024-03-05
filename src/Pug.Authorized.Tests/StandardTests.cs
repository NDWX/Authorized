using System.Diagnostics.CodeAnalysis;
using Xunit;

namespace Pug.Authorized.Tests;

[SuppressMessage( "ReSharper", "HeapView.DelegateAllocation" )]
public class StandardTests : IClassFixture<StandardTestContext>
{
	internal StandardTestContext TestContext { get; }

	public StandardTests( StandardTestContext testContext )
	{
		TestContext = testContext;
	}

	/*
	[Fact]
	[Order( 0 )]
	public async Task UserNotGrantedPermissionShouldNotBeAuthorizedAsync()
	{
		Permissions permissions = await TestContext.Authorized.IsAuthorizedAsync(
										new Noun
										{
											Type = SubjectTypes.User,
											Identifier = "user"
										},
										AdministrativeActions.ManagePermissions,
										new DomainObject
										{
											Domain = string.Empty,
											Object = new Noun()
											{
												Type = "OBJECT",
												Identifier = "DEFAULT"
											}
										},
										new Dictionary<string, IEnumerable<string>>(),
										string.Empty
									);

		Assert.Equal( Permissions.Denied, permissions );
	}

	[Fact]
	public async Task UserWithPermissionShouldBeAuthorizedAsync()
	{
		Assert.Equal(
				Permissions.Allowed,
				await TestContext.Authorized.IsAuthorizedAsync(
						new Noun
						{
							Type = SubjectTypes.User,
							Identifier = "administrator"
						},
						AdministrativeActions.ManagePermissions,
						new DomainObject
						{
							Domain = string.Empty,
							Object = new Noun()
							{
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
	public async Task UnknownUserShouldNotBeGrantedPermissionAsync()
	{
		Assert.Equal(
				Permissions.Denied,
				await TestContext.Authorized.IsAuthorizedAsync(
						new Noun
						{
							Type = SubjectTypes.User,
							Identifier = "unknown"
						},
						AdministrativeActions.ManagePermissions,
						new DomainObject
						{
							Domain = string.Empty,
							Object = new Noun()
							{
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
	public async Task UserWithAuthorizedRoleShouldBeAuthorizedAsync()
	{
		Assert.Equal(
				Permissions.Allowed,
				await TestContext.Authorized.IsAuthorizedAsync(
						new Noun
						{
							Type = SubjectTypes.User,
							Identifier = "unknown"
						},
						AdministrativeActions.ViewPermissions,
						new DomainObject
						{
							Domain = string.Empty,
							Object = new Noun()
							{
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
	public async Task UserWithUnknownRoleShouldNotBeAuthorizedAsync()
	{
		Assert.Equal(
				Permissions.Denied,
				await TestContext.Authorized.IsAuthorizedAsync(
						new Noun
						{
							Type = SubjectTypes.User,
							Identifier = "user"
						},
						AdministrativeActions.ManagePermissions,
						new DomainObject
						{
							Domain = string.Empty,
							Object = new Noun()
							{
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
	public async Task DefaultAdminsitratorGroupUserShouldBeAllowedToManagePermissionsAsync()
	{
		TestContext.SetCurrentUser( "administrator" );

		await TestContext.Authorized.SetAccessControlEntriesAsync(
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
				new Noun
				{
					Type = SubjectTypes.User,
					Identifier = "user"
				},
				new[]
				{
					new AccessControlEntryDefinition()
					{
						Action = "VIEW",
						Permissions = Permissions.Allowed
					}
				}
			);
	}

	[Fact]
	public async Task MembersOfPermittedGroupShouldBeAllowedToManagePermissionsAsync()
	{
		TestContext.SetCurrentUser( "sysadmin" );

		await TestContext.Authorized.SetAccessControlEntriesAsync(
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
				new Noun
				{
					Type = SubjectTypes.User,
					Identifier = "user"
				},
				new[]
				{
					new AccessControlEntryDefinition()
					{
						Action = "VIEW",
						Permissions = Permissions.Allowed,
						Context = new AccessControlContextEntry[] { }
					}
				}
			);
	}

	[Fact]
	public async Task MembersOfRestrictedGroupShouldNotBeAllowedToManagePermissions()
	{
		TestContext.SetCurrentUser( "poweruser" );

		Assert.Throws<NotAuthorized>( () =>
				{
					TestContext.Authorized.SetAccessControlEntriesAsync(
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
							new Noun
							{
								Type = SubjectTypes.User,
								Identifier = "user"
							},
							new[]
							{
								new AccessControlEntryDefinition()
								{
									Action = "VIEW",
									Permissions = Permissions.Allowed
								}
							}
						).ConfigureAwait( false ).GetAwaiter().GetResult();
				}
			);
	}*/
}