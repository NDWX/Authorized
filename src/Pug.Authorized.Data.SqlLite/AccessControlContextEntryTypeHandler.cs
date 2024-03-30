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
		parameter.Value = JsonSerializer.Serialize( value, SerializerOptions);
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