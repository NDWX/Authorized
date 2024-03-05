using System;
using System.Data.SQLite;
using System.IO;
using Pug.Authorize.Data.SqlLite;

namespace Pug.Authorized.Tests;

public class StandardTestContext
{
	private readonly DateTime _testStartDateTime = DateTime.Now;
	private const string DataStoreLocation = @".\testDataStore.sqlite";
	private readonly DummySessionUserIdentityAccessor _dummySessionUserIdentityAccessor;
	private readonly DefaultIdentifierGenerator _identifierGenerator;

	public AuthorizationDataStore DataStore { get; }
	public IAuthorized Authorized { get; }

	public DateTime TestStartDateTime => _testStartDateTime;

	public string GenerateNewIdentifier() => _identifierGenerator.GetNext();

	public StandardTestContext()
	{
		_dummySessionUserIdentityAccessor = new DummySessionUserIdentityAccessor();

		if( File.Exists( DataStoreLocation ) )
		{
			File.Delete( DataStoreLocation );
		}

		AuthorizationDataStore.Create( DataStoreLocation );

		DataStore = new AuthorizationDataStore($"data source={DataStoreLocation}", SQLiteFactory.Instance);
		_identifierGenerator = new DefaultIdentifierGenerator();
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
	}

	public void SetCurrentUser(string username)
	{
		_dummySessionUserIdentityAccessor.User = username;
	}
}