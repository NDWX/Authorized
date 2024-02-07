
using System.Data;
using System.Data.SQLite;
using Dapper;
using Pug.Application.Data;
using Pug.Authorized;
using Pug.Authorized.Data;
using Pug.Effable;

namespace Pug.Authorize.Data.SqlLite;

public class AuthorizationDataStore : ApplicationDataSession, IAuthorizedDataStore
{
	public AuthorizationDataStore( IDbConnection databaseSession ) : base( databaseSession )
	{
		SqlMapper.AddTypeHandler( DateTimeTypeHandler.Instance );
		SqlMapper.AddTypeHandler( AccessControlContextEntryTypeHandler.Instance );
	}
	public async Task<IEnumerable<AccessControlEntry>> GetAccessControlEntriesAsync( string purpose, DomainObject domainObject, Noun subject, string action = null )
	{
		return await Connection
				.QueryAsync<AccessControlEntryDefinition, AccessControlEntry, DateTime?, Reference,
						DateTime?, Reference, AccessControlEntry>(
						@"select action, context, permissions, identifier,
                           	registrationTimestamp as timestamp, registrantType as type, registrantIdentifier as identifier, 
                           	lastUpdateTimestamp as timestamp, lastUpdaterType as type, lastUpdaterIdentifier as identifier
							where domain = @domain and purpose = @purpose 
								and objectType = @objectType and objectIdentifier = @objectIdentifier
								and subjectType = @subjectType and subjectIdentifier = @subjectIdentifier",
						param: new
						{
							domain = domainObject.Domain,
							purpose,
							objectType = domainObject.Object.Type,
							objectIdentifier = domainObject.Object.Identifier,
							subjectType = subject.Type,
							subjectIdentifier = subject.Identifier
						},
						splitOn: "identifier, action, identifier, timestamp, type, timestamp, type",
						map: ( definition, entry, registrationTimestamp, registrar, lastUpdateTimestamp, lastUpdater ) =>
							entry with
									{
										Definition = definition,
										Registration = new ActionContext()
											{ Actor = registrar, Timestamp = registrationTimestamp!.Value },
										LastUpdate = lastUpdateTimestamp == null
														? null
														: new ActionContext()
															{ Actor = lastUpdater, Timestamp = lastUpdateTimestamp.Value }
									}
					);
	}

	public async Task<IDictionary<Noun, IEnumerable<AccessControlEntry>>> GetAccessControlListsAsync( string purpose, DomainObject domainObject )
	{
		IEnumerable<KeyValuePair<Noun, AccessControlEntry>> entries =
			await Connection
				.QueryAsync<Noun, AccessControlEntryDefinition, AccessControlEntry, DateTime?, Reference,
						DateTime?, Reference, KeyValuePair<Noun, AccessControlEntry>>(
						@"select subjectType as type, subjectIdentifier as identifier, action, context, permissions, identifier,
                           	registrationTimestamp as timestamp, registrantType as type, registrantIdentifier as identifier, 
                           	lastUpdateTimestamp as timestamp, lastUpdaterType as type, lastUpdaterIdentifier as identifier
							where domain = @domain and purpose = @purpose and objectType = @objectType and objectIdentifier = @objectIdentifier",
						param: new
						{
							domain = domainObject.Domain,
							purpose,
							objectType = domainObject.Object.Type,
							objectIdentifier = domainObject.Object.Identifier
						},
						splitOn: "identifier, action, identifier, timestamp, type, timestamp, type",
						map: ( subject, definition, entry, registrationTimestamp, registrar, lastUpdateTimestamp, lastUpdater ) =>
							new KeyValuePair<Noun, AccessControlEntry>(
									subject,
									entry with
									{
										Definition = definition,
										Registration = new ActionContext()
											{ Actor = registrar, Timestamp = registrationTimestamp!.Value },
										LastUpdate = lastUpdateTimestamp == null
														? null
														: new ActionContext()
															{ Actor = lastUpdater, Timestamp = lastUpdateTimestamp.Value }
									}
								)
					);

		return entries
				.GroupBy( x => x.Key,
						( subject, entries ) =>
							new KeyValuePair<Noun, IEnumerable<AccessControlEntry>>(
									subject,
									entries.Select( x => x.Value )
								)
					)
				.ToDictionary( x => x.Key, x => x.Value );
	}

	public async Task DeleteAccessControlEntriesAsync( string purpose, DomainObject domainObject, Noun subject = null )
	{
		await Connection.ExecuteAsync(
				@"delete from authorizations 
       					where purpose = @purpose and domain = @domain and 
       					      objectType = @objectIdentifier and objectType = @objectType and
       					      subjectType = @subjectType and subjectIdentifier = @subjectIdentifier",
				new
				{
					domain = domainObject.Domain,
					purpose,
					objectType = domainObject.Object.Type,
					objectIdentifier = domainObject.Object.Identifier,
					subjectType = subject.Type,
					subjectIdentifier = subject.Identifier
				}
			);
	}

	public async Task<bool> AccessControlEntryExistsAsync( string identifier )
	{
		int rows = await Connection.ExecuteScalarAsync<int>(
							"select count(action) from authorizations where identifier = @identifier",
							new { identifier }
						);

		return rows > 0;
	}

	public async Task InsertAsync( string purpose, DomainObject domainObject, Noun subject, AccessControlEntry accessControlEntry )
	{
		int rows = await Connection.ExecuteAsync(
				@"insert into authorizations(identifier, domain, purpose, objectType, objectIdentifier, 
												subjectType, subjectIdentifier, action, context, permissions, 
                           						registrationTimestamp, registrantType, registrantIdentifier, 
                           						lastUpdateTimestamp, lastUpdaterType, lastUpdaterIdentifier)
                           				values(@identifier, @domain, @purpose, @objectType, @objectIdentifier, 
												@subjectType, @subjectIdentifier, @action, @context, @permission, 
                           						@registrationTimestamp, @registrantType, @registrantIdentifier, 
                           				       	@lastUpdateTimestamp, @lastUpdaterType, @lastUpdaterIdentifier)",
				new
				{
					identifier = accessControlEntry.Identifier,
					domain = domainObject.Domain,
					purpose,
					objectType = domainObject.Object.Type,
					objectIdentifier = domainObject.Object.Identifier,
					subjectType = subject.Type,
					subjectIdentifier = subject.Identifier,
					action = accessControlEntry.Definition.Action,
					context = accessControlEntry.Definition.Context,
					permissions = accessControlEntry.Definition.Permissions,
					registrationTimestamp = accessControlEntry.Registration.Timestamp,
					registrantType = accessControlEntry.Registration.Actor.Type,
					registrantIdentifier = accessControlEntry.Registration.Actor.Identifier,
					lastUpdateTimestamp = accessControlEntry.LastUpdate?.Timestamp,
					lastUpdaterType = accessControlEntry.LastUpdate?.Actor.Type,
					lastUpdaterIdentifier = accessControlEntry.LastUpdate?.Actor.Identifier
				},
				commandType: CommandType.Text
			);

		if( rows < 0 )
			throw new DataException( "Unable to insert AccessControlEntry record" );
	}

	public static void CreateStore( string path )
	{
		path = Environment.ExpandEnvironmentVariables( path );
		
		path = Path.GetFullPath( path );

		if( File.Exists( path ) )
			throw new ArgumentException( "Specified file already exists.", nameof(path) );

		using SQLiteConnection connection = new ( $"Data Source={path}" );

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
    					lastUpdaterIdentifier text not null default ''
    				);", CommandType.Text, null, CommandBehavior.CloseConnection, 10 );
		
		connection.Execute( command );
	}
}