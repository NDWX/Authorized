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
	internal StandardTestContext TestContext { get; }

	public SqliteStoreTest( StandardTestContext testContext )
	{
		TestContext = testContext;

	}

	[Fact]
	[Order( 0 )]
	public async Task InsertAccessControlEntryShouldWork()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		await dataSession.InsertAsync( StandardTestContext.Purpose,
								StandardTestContext.Object1,
								StandardTestContext.User1,
								StandardTestContext.ViewAccessControlEntry

			);

		Assert.True(
			await dataSession.AccessControlEntryExistsAsync( StandardTestContext.ViewAccessControlEntry.Identifier )
			);
	}

	[Fact]
	public async Task DuplicateAccessControlEntryShouldFail()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		await Assert.ThrowsAnyAsync<Exception>(
				() =>
					dataSession.InsertAsync( StandardTestContext.Purpose,
											StandardTestContext.Object1,
											StandardTestContext.User1,
											StandardTestContext.ViewAccessControlEntry

						)
			);
	}

	[Fact]
	public async Task RetrieveAccessControlEntryShouldWork()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		IEnumerable<AccessControlEntry> accessControlEntries =
			await dataSession.GetAccessControlEntriesAsync( StandardTestContext.Purpose, StandardTestContext.Object1, StandardTestContext.User1, TestActions.View );

		Assert.NotEmpty(accessControlEntries);

		Assert.Equal( Permissions.Allowed , accessControlEntries.First().Definition.Permissions);

		Assert.Equal( TestContext.TestStartDateTime, accessControlEntries.First().Registration.Timestamp );
	}

	[Fact]
	public async Task GetAccessControlEntriesWithSpecificActionShouldWorkCorrectly()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		string identifier = $"{StandardTestContext.ViewAccessControlEntry.Identifier}_1";

		await dataSession.InsertAsync(
				StandardTestContext.Purpose,
				StandardTestContext.Object1,
				StandardTestContext.User1,
				StandardTestContext.ViewAccessControlEntry with
				{
					Identifier = identifier,
					Definition = StandardTestContext.ViewAccessControlEntry.Definition with { Action = "UPDATE" }
				}
			);

		IEnumerable<AccessControlEntry> entries =
			await dataSession.GetAccessControlEntriesAsync( StandardTestContext.Purpose, StandardTestContext.Object1, StandardTestContext.User1 );

		Assert.True( entries.Count() == 2 );
	}

	[Fact]
	public async Task GetAccessControlEntriesWithWildcardActionShouldWorkCorrectly()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		IEnumerable<AccessControlEntry> entries =
			await dataSession.GetAccessControlEntriesAsync( StandardTestContext.Purpose, StandardTestContext.Object1, StandardTestContext.User1, "UPDATE" );

		Assert.True( entries.Count() == 1 && entries.First().Definition.Action == "UPDATE" );

		entries =
			await dataSession.GetAccessControlEntriesAsync( StandardTestContext.Purpose, StandardTestContext.Object1, StandardTestContext.User1, "VIEW" );

		Assert.True( entries.Count() == 1 && entries.First().Definition.Action == "VIEW" );
	}

	[Fact]
	public async Task GetAccessControlListShouldReturnAllRelevantEntries()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		IDictionary<Noun, IEnumerable<AccessControlEntry>> list =
			await dataSession.GetAccessControlListsAsync( StandardTestContext.Purpose, StandardTestContext.Object1 );

		Assert.True( list.Count == 1 && list.ContainsKey( StandardTestContext.User1 ) && list[StandardTestContext.User1].Count() == 2 );

		list =
			await dataSession.GetAccessControlListsAsync( StandardTestContext.Purpose, StandardTestContext.Object1  with { Domain = "UNKNOWN"});

		Assert.True( list.Count == 0 );
	}

	[Fact]
	public async Task DeleteAccessControlEntriesShouldWorkCorrectly()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		await dataSession.DeleteAccessControlEntriesAsync( StandardTestContext.Purpose, StandardTestContext.Object1, StandardTestContext.User1 );

		IEnumerable<AccessControlEntry> entries =
			await dataSession.GetAccessControlEntriesAsync( StandardTestContext.Purpose, StandardTestContext.Object1, StandardTestContext.User1 );

		Assert.True( !entries.Any() );
	}

}