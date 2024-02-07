using System.Data;
using Dapper;

namespace Pug.Authorize.Data.SqlLite;

internal class DateTimeTypeHandler : SqlMapper.TypeHandler<DateTime?>
{
	public override void SetValue( IDbDataParameter parameter, DateTime? value )
	{
		long? ticks = null;

		if( value.HasValue )
			ticks = value.Value.ToUniversalTime().Ticks;

		parameter.Value = ticks;
	}

	public override DateTime? Parse( object value )
	{
		return DBNull.Value.Equals( value )
					? null
					: new DateTime( (long)value, DateTimeKind.Utc );
	}

	private static readonly DateTimeTypeHandler instance = new ();

	public static DateTimeTypeHandler Instance => instance;
}