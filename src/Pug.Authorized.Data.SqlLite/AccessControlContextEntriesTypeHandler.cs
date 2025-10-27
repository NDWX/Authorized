using System.Data;
using System.Text.Json;
using Dapper;
using Pug.Authorized;

namespace Pug.Authorize.Data.SqlLite;

internal class AccessControlContextEntriesTypeHandler
	: SqlMapper.TypeHandler<IEnumerable<AccessControlContextEntry>>
{
	private static readonly JsonSerializerOptions SerializerOptions = new ()
	{
		WriteIndented = false,
		PropertyNameCaseInsensitive = true
	};

	public override void SetValue( IDbDataParameter parameter, IEnumerable<AccessControlContextEntry>? value )
	{
		parameter.Value = JsonSerializer.Serialize( value, SerializerOptions );
	}

	public override IEnumerable<AccessControlContextEntry>? Parse( object value )
	{
		return DBNull.Value.Equals( value ) ?
					null :
					JsonSerializer.Deserialize<IEnumerable<AccessControlContextEntry>>(
						(string)value,
						SerializerOptions
					);
	}

	private static readonly AccessControlContextEntriesTypeHandler instance = new ();

	public static AccessControlContextEntriesTypeHandler Instance => instance;
}