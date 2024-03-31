using System;
using System.Collections.Generic;
using System.Diagnostics.CodeAnalysis;
using System.Linq;
using System.Threading.Tasks;
using Pug.Authorize.Data.SqlLite;
using Pug.Effable;
using Xunit;
using Xunit.Extensions.Ordering;

namespace Pug.Authorized.Tests;

public static class TestActions
{
	public const string View = "VIEW";
}

[SuppressMessage( "ReSharper", "HeapView.DelegateAllocation" )]
public class SqliteStoreTest : IClassFixture<StandardTestContext>
{
	private static readonly DomainObject Object1 = new ()
	{
		Domain = "DEFAULT", Object = new Noun()
		{
			Type = "OBJECT", Identifier = "OBJECT1"

		}
	};

	private static readonly Noun User1 = new () { Type = SubjectTypes.User, Identifier = "USER1" };

	private static AccessControlEntry ViewAccessControlEntry { get; set; }


	internal StandardTestContext TestContext { get; }

	public SqliteStoreTest( StandardTestContext testContext )
	{
		ViewAccessControlEntry = new AccessControlEntry()
		{
			Identifier = testContext.GenerateNewIdentifier(),
			Definition = new AccessControlEntryDefinition()
			{
				Action = TestActions.View,
				Permissions = Permissions.Allowed,
				Context = Array.Empty<AccessControlContextEntry>()
			},
			Registration = new ActionContext()
			{
				Actor = new Reference()
				{
					Type = "USER", Identifier = "ADMINISTRATOR"
				},
				Timestamp = testContext.TestStartDateTime
			}
		};

		TestContext = testContext;

	}

	[Fact]
	[Order( 0 )]
	public async Task InsertAccessControlEntryShouldWork()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		await dataSession.InsertAsync( StandardTestContext.Purpose,
								Object1,
								User1,
								ViewAccessControlEntry

			);

		Assert.True(
			await dataSession.AccessControlEntryExistsAsync( ViewAccessControlEntry.Identifier )
			);
	}

	[Fact]
	public async Task DuplicateAccessControlEntryShouldFail()
	{
		// ReSharper disable once HeapView.ClosureAllocation
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		await Assert.ThrowsAnyAsync<Exception>(
				() =>
					dataSession.InsertAsync( StandardTestContext.Purpose,
											Object1,
											User1,
											ViewAccessControlEntry

						)
			);
	}

	[Fact]
	public async Task RetrieveAccessControlEntryShouldWork()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		IEnumerable<AccessControlEntry> accessControlEntries =
			await dataSession.GetAccessControlEntriesAsync( StandardTestContext.Purpose, Object1, User1, TestActions.View );

		Assert.NotEmpty(accessControlEntries);

		Assert.Equal( Permissions.Allowed , accessControlEntries.First().Definition.Permissions);

		Assert.Equal( TestContext.TestStartDateTime, accessControlEntries.First().Registration.Timestamp );
	}

	[Fact]
	public async Task GetAccessControlEntriesWithSpecificActionShouldWorkCorrectly()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		string identifier = $"{ViewAccessControlEntry.Identifier}_1";

		await dataSession.InsertAsync(
				StandardTestContext.Purpose,
				Object1,
				User1,
				ViewAccessControlEntry with
				{
					Identifier = identifier,
					Definition = ViewAccessControlEntry.Definition with { Action = "UPDATE" }
				}
			);

		IEnumerable<AccessControlEntry> entries =
			await dataSession.GetAccessControlEntriesAsync( StandardTestContext.Purpose, Object1, User1 );

		Assert.True( entries.Count() == 2 );
	}

	[Fact]
	public async Task GetAccessControlEntriesWithWildcardActionShouldWorkCorrectly()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		IEnumerable<AccessControlEntry> entries =
			await dataSession.GetAccessControlEntriesAsync( StandardTestContext.Purpose, Object1, User1, "UPDATE" );

		Assert.True( entries.Count() == 1 && entries.First().Definition.Action == "UPDATE" );

		entries =
			await dataSession.GetAccessControlEntriesAsync( StandardTestContext.Purpose, Object1, User1, "VIEW" );

		Assert.True( entries.Count() == 1 && entries.First().Definition.Action == "VIEW" );
	}

	[Fact]
	public async Task GetAccessControlListShouldReturnAllRelevantEntries()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		IDictionary<Noun, IEnumerable<AccessControlEntry>> list =
			await dataSession.GetAccessControlListsAsync( StandardTestContext.Purpose, Object1 );

		Assert.True( list.Count == 1 && list.ContainsKey( User1 ) && list[User1].Count() == 2 );

		list =
			await dataSession.GetAccessControlListsAsync( StandardTestContext.Purpose, Object1  with { Domain = "UNKNOWN"});

		Assert.True( list.Count == 0 );
	}

	[Fact]
	public async Task DeleteAccessControlEntriesShouldWorkCorrectly()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		await dataSession.DeleteAccessControlEntriesAsync( StandardTestContext.Purpose, Object1, User1 );

		IEnumerable<AccessControlEntry> entries =
			await dataSession.GetAccessControlEntriesAsync( StandardTestContext.Purpose, Object1, User1 );

		Assert.True( !entries.Any() );
	}

}