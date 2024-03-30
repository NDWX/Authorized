using System;
using System.Data.SQLite;
using System.IO;
using System.Threading;
using Pug.Authorize.Data.SqlLite;
using Pug.Effable;

namespace Pug.Authorized.Tests;

public class StandardTestContext : IDisposable
{
	public static readonly string Purpose = "TEST";

	public static readonly DomainObject Object1 = new ()
	{
		Domain = "DEFAULT", Object = new Noun()
		{
			Type = "OBJECT", Identifier = "OBJECT1"

		}
	};

	public static readonly Noun User1 = new () { Type = SubjectTypes.User, Identifier = "USER1" };

	private static AccessControlEntry viewAccessControlEntry;
	public static AccessControlEntry ViewAccessControlEntry => viewAccessControlEntry;


	private readonly DateTime _testStartDateTime = DateTime.Now;
	private readonly string DataStoreLocation;
	private readonly DummySessionUserIdentityAccessor _dummySessionUserIdentityAccessor;
	private readonly DefaultIdentifierGenerator _identifierGenerator;

	public AuthorizationDataStore DataStore { get; }
	public IAuthorized Authorized { get; }

	public DateTime TestStartDateTime => _testStartDateTime;

	public string GenerateNewIdentifier() => _identifierGenerator.GetNext();

	public StandardTestContext()
	{
		DataStoreLocation = $".\\{DateTime.Now.Ticks.ToString()}.sqlite";

		while( File.Exists( DataStoreLocation ) )
		{
			Thread.Sleep( new Random().Next(1, 1000) );
			DataStoreLocation = $".\\{DateTime.Now.Ticks.ToString()}.sqlite";
		}

		AuthorizationDataStore.Create( DataStoreLocation );

		DataStore = new AuthorizationDataStore($"data source={DataStoreLocation}", SQLiteFactory.Instance);

		_identifierGenerator = new DefaultIdentifierGenerator();

		_dummySessionUserIdentityAccessor = new DummySessionUserIdentityAccessor();

		Authorized = new Authorized(
				new Options
				{
					ManagementDomain = string.Empty,
					AdministratorRole = "ADMINISTRATORS",
					AdministrativeActionGrantees = AdministrativeActionGrantees.AllowedUsers
				},
				_identifierGenerator,
				_dummySessionUserIdentityAccessor,
				new DummyUserRoleProvider(),
				DataStore
			);

		viewAccessControlEntry = new AccessControlEntry()
		{
			Identifier = _identifierGenerator.GetNext(),
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
				Timestamp = TestStartDateTime
			}
		};
	}

	public void SetCurrentUser(string username)
	{
		_dummySessionUserIdentityAccessor.User = username;
	}

	public void Dispose()
	{
		File.Delete( DataStoreLocation );
	}
}