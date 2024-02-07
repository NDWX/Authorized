using System.Data;
using System.Text.Json;
using Dapper;
using Pug.Authorized;

namespace Pug.Authorize.Data.SqlLite;

internal class AccessControlContextEntryTypeHandler : SqlMapper.TypeHandler<AccessControlContextEntry>
{
	private static readonly JsonSerializerOptions SerializerOptions = new ()
	{
		WriteIndented = false,
		PropertyNameCaseInsensitive = true
	};

	public override void SetValue( IDbDataParameter parameter, AccessControlContextEntry? value )
	{
		string json = null;

		if( value is not null )
			json = JsonSerializer.Serialize( value, SerializerOptions );

		parameter.Value = json;
	}

	public override AccessControlContextEntry? Parse( object value )
	{
		return DBNull.Value.Equals( value )
					? null
					: JsonSerializer.Deserialize<AccessControlContextEntry>( (string)value, SerializerOptions );
	}

	private static readonly AccessControlContextEntryTypeHandler instance = new ();

	public static AccessControlContextEntryTypeHandler Instance => instance;
}