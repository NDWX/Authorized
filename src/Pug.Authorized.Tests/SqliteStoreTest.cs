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

	private readonly string purpose = "TEST";

	private readonly DomainObject _object1 = new ()
	{
		Domain = "DEFAULT", Object = new Noun()
		{
			Type = "OBJECT", Identifier = "OBJECT1"

		}
	};

	private readonly Noun _user1 = new () { Type = "USER", Identifier = "USER1" };
	private readonly AccessControlEntry _viewAccessControlEntry;

	public SqliteStoreTest( StandardTestContext testContext )
	{
		TestContext = testContext;

		_viewAccessControlEntry = new AccessControlEntry()
		{
			Identifier = TestContext.GenerateNewIdentifier(),
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
	}

	[Fact]
	[Order( 0 )]
	public async Task InsertAccessControlEntryShouldWork()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		await dataSession.InsertAsync( purpose,
								_object1,
								_user1,
								_viewAccessControlEntry

			);

		Assert.True(
			await dataSession.AccessControlEntryExistsAsync( _viewAccessControlEntry.Identifier )
			);
	}

	[Fact]
	public async Task DuplicateAccessControlEntryShouldFail()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		await Assert.ThrowsAnyAsync<Exception>(
				() =>
					dataSession.InsertAsync( purpose,
											_object1,
											_user1,
											_viewAccessControlEntry

						)
			);
	}

	[Fact]
	public async Task RetrieveAccessControlEntryShouldWork()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		IEnumerable<AccessControlEntry> accessControlEntries =
			await dataSession.GetAccessControlEntriesAsync( purpose, _object1, _user1, TestActions.View );

		Assert.NotEmpty(accessControlEntries);

		Assert.Equal( Permissions.Allowed , accessControlEntries.First().Definition.Permissions);

		Assert.Equal( TestContext.TestStartDateTime, accessControlEntries.First().Registration.Timestamp );
	}

	[Fact]
	public async Task GetAccessControlEntriesWithSpecificActionShouldWorkCorrectly()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		string identifier = $"{_viewAccessControlEntry.Identifier}_1";

		await dataSession.InsertAsync(
				purpose,
				_object1,
				_user1,
				_viewAccessControlEntry with
				{
					Identifier = identifier,
					Definition = _viewAccessControlEntry.Definition with { Action = "UPDATE" }
				}
			);

		IEnumerable<AccessControlEntry> entries =
			await dataSession.GetAccessControlEntriesAsync( purpose, _object1, _user1 );

		Assert.True( entries.Count() == 2 );
	}

	[Fact]
	public async Task GetAccessControlEntriesWithWildcardActionShouldWorkCorrectly()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		IEnumerable<AccessControlEntry> entries =
			await dataSession.GetAccessControlEntriesAsync( purpose, _object1, _user1, "UPDATE" );

		Assert.True( entries.Count() == 1 && entries.First().Definition.Action == "UPDATE" );

		entries =
			await dataSession.GetAccessControlEntriesAsync( purpose, _object1, _user1, "VIEW" );

		Assert.True( entries.Count() == 1 && entries.First().Definition.Action == "VIEW" );
	}

	[Fact]
	public async Task GetAccessControlListShouldReturnAllRelevantEntries()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		IDictionary<Noun, IEnumerable<AccessControlEntry>> list =
			await dataSession.GetAccessControlListsAsync( purpose, _object1 );

		Assert.True( list.Count == 1 && list.ContainsKey( _user1 ) && list[_user1].Count() == 2 );

		list =
			await dataSession.GetAccessControlListsAsync( purpose, _object1  with { Domain = "UNKNOWN"});

		Assert.True( list.Count == 0 );
	}

	[Fact]
	public async Task DeleteAccessControlEntriesShouldWorkCorrectly()
	{
		using AuthorizationDataSession dataSession = TestContext.DataStore.GetSession();

		await dataSession.DeleteAccessControlEntriesAsync( purpose, _object1, _user1 );

		IEnumerable<AccessControlEntry> entries =
			await dataSession.GetAccessControlEntriesAsync( purpose, _object1, _user1 );

		Assert.True( !entries.Any() );
	}

}