using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Threading.Tasks;
using Pug.Application.Security;
using Xunit;
using Xunit.Extensions.Ordering;

namespace Pug.Authorized.Tests;

[SuppressMessage( "ReSharper", "HeapView.DelegateAllocation" )]
public class StandardTests : IClassFixture<StandardTestContext>
{
	internal StandardTestContext TestContext { get; }

	private readonly Noun userSubject = new Noun()
	{
		Type = SubjectTypes.User,
		Identifier = DummyUserRoleProvider._user
	};

	private readonly Noun user2Subject = new Noun()
	{
		Type = SubjectTypes.User,
		Identifier = "USER2"
	};

	private readonly Noun group1Subject = new Noun()
	{
		Type = SubjectTypes.Group,
		Identifier = "GROUP1"
	};

	private readonly Noun group2Subject = new Noun()
	{
		Type = SubjectTypes.Group,
		Identifier = "GROUP2"
	};

	private readonly Noun _object1 = new Noun()
	{
		Type = "OBJECT",
		Identifier = "OBJECT1"
	};

	private readonly Noun _object2 = new Noun()
	{
		Type = "OBJECT",
		Identifier = "OBJECT2"
	};

	private readonly DomainObject _domainObject1;
	private readonly DomainObject _domainObject2;

	public StandardTests( StandardTestContext testContext )
	{
		TestContext = testContext;

		_domainObject1 = new DomainObject
		{
			Domain = string.Empty,
			Object = _object1
		};

		_domainObject2 = new DomainObject
		{
			Domain = string.Empty,
			Object = _object2
		};
	}

	[Fact]
	[Order( 0 )]
	public async Task MemberOfAdministratorsGroupShouldBeAllowedToSetPermissions()
	{
		TestContext.SetCurrentUser( DummyUserRoleProvider._administrator );

		await TestContext.Authorized.SetAccessControlListsAsync(
				StandardTestContext.Purpose,
				_domainObject1,
				new Dictionary<Noun, IEnumerable<AccessControlEntryDefinition>>()
				{
					[userSubject] = new[]
					{
						new AccessControlEntryDefinition()
						{
							Action = "READ",
							Permissions = Permissions.Allowed,
							Context = Array.Empty<AccessControlContextEntry>()
						},
						new AccessControlEntryDefinition()
						{
							Action = "MODIFY",
							Permissions = Permissions.Denied,
							Context = Array.Empty<AccessControlContextEntry>()
						}
					},
					[group1Subject] = new[]
					{
						new AccessControlEntryDefinition()
						{
							Action = "DELETE",
							Permissions = Permissions.Denied,
							Context = Array.Empty<AccessControlContextEntry>()
						}
					}
				}
			);

		await TestContext.Authorized.SetAccessControlListsAsync(
				StandardTestContext.Purpose,
				_domainObject2,
				new Dictionary<Noun, IEnumerable<AccessControlEntryDefinition>>()
				{
					[userSubject] = new[]
					{
						new AccessControlEntryDefinition()
						{
							Action = "READ",
							Permissions = Permissions.Allowed,
							Context = Array.Empty<AccessControlContextEntry>()
						},
						new AccessControlEntryDefinition()
						{
							Action = "MODIFY",
							Permissions = Permissions.Denied,
							Context = Array.Empty<AccessControlContextEntry>()
						}
					},
					[group2Subject] = new[]
					{
						new AccessControlEntryDefinition()
						{
							Action = "READ",
							Permissions = Permissions.Denied,
							Context = Array.Empty<AccessControlContextEntry>()
						},
						new AccessControlEntryDefinition()
						{
							Action = "DELETE",
							Permissions = Permissions.Allowed,
							Context = Array.Empty<AccessControlContextEntry>()
						}
					}
				}
			);

		Assert.True( true );
	}

	[Fact]
	public async Task MemberOfNonAdministratorsGroupShouldNotBeAllowedToSetPermissions()
	{
		TestContext.SetCurrentUser( DummyUserRoleProvider._user );

		await Assert.ThrowsAsync<NotAuthorized>(
				() =>
					TestContext.Authorized.SetAccessControlEntriesAsync(
							StandardTestContext.Purpose,
							_domainObject1, userSubject, new[]
							{
								new AccessControlEntryDefinition()
								{
									Action = "DELETE",
									Permissions = Permissions.Allowed,
									Context = Array.Empty<AccessControlContextEntry>()
								}
							}
						)
			);
	}

	[Fact]
	public async Task UserNotGrantedPermissionShouldNotBeAuthorizedAsync()
	{
		Permissions permissions = await TestContext.Authorized.IsAuthorizedAsync(
										userSubject,
										"MODIFY",
										_domainObject1,
										new Dictionary<string, IEnumerable<string>>(),
										StandardTestContext.Purpose
									);

		Assert.Equal( Permissions.Denied, permissions );
	}

	[Fact]
	public async Task UserWithExplicitPermissionShouldBeAuthorizedAsync()
	{
		Assert.Equal(
				Permissions.Allowed,
				await TestContext.Authorized.IsAuthorizedAsync(
						userSubject,
						"READ",
						_domainObject1,
						new Dictionary<string, IEnumerable<string>>(),
						StandardTestContext.Purpose
					)
			);
	}

	[Fact]
	public async Task UserWithInheritedPermissionShouldBeAuthorizedAsync()
	{
		Assert.Equal(
				Permissions.Allowed,
				await TestContext.Authorized.IsAuthorizedAsync(
						user2Subject,
						"DELETE",
						_domainObject2,
						new Dictionary<string, IEnumerable<string>>(),
						StandardTestContext.Purpose
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
						StandardTestContext.Purpose
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
						StandardTestContext.Purpose
					)
			);
	}

}