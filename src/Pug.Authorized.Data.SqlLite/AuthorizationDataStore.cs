using System.Data;
using System.Data.Common;
using System.Data.SQLite;
using Pug.Application.Data;

namespace Pug.Authorize.Data.SqlLite;

public class AuthorizationDataStore : ApplicationData<AuthorizationDataSession>
{
	public AuthorizationDataStore( string location, DbProviderFactory dataProvider ) : base( location, dataProvider )
	{
	}

	protected override AuthorizationDataSession CreateApplicationDataSession( IDbConnection databaseSession,
																			DbProviderFactory dataAccessProvider )
	{
		return new AuthorizationDataSession( databaseSession );
	}

	protected override IEnumerable<SchemaVersion> InitializeUpgradeScripts()
	{
		return Array.Empty<SchemaVersion>();
	}

	public static void Create( string path )
	{
		path = Environment.ExpandEnvironmentVariables( path );

		path = Path.GetFullPath( path );

		if( File.Exists( path ) )
			throw new ArgumentException( "Specified file already exists.", nameof(path) );

		CommandInfo command = new (
			@$"create table authorizations(
    					identifier text not null,
    					domain text not null,
    					purpose text not null,
    					objectType text not null,
    					objectIdentifier text not null,
    					subjectType text not null,
    					subjectIdentifier text not null,
    					action text not null,
    					context text not null,
    					permissions text not null,
    					registrationTimestamp integer not null,
    					registrantType text not null,
    					registrantIdentifier text not null,
    					lastUpdateTimestamp integer,
    					lastUpdaterType text not null default '',
    					lastUpdaterIdentifier text not null default '',
    					constraint authorization_pk primary key (identifier) on conflict fail,
    					constraint authorization_object_subject_action_uq unique (domain, purpose, objectType, objectIdentifier, subjectType, subjectIdentifier, action) on conflict fail
    				);", CommandType.Text, Array.Empty<IDbDataParameter>(), CommandBehavior.CloseConnection, 10 );

		using SQLiteConnection connection = new ( $"Data Source={path}" );

		connection.Open();
		connection.Execute( command );
	}
}