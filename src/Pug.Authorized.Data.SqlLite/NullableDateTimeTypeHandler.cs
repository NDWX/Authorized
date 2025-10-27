using System.Data;
using Dapper;

namespace Pug.Authorize.Data.SqlLite;

internal class NullableDateTimeTypeHandler : SqlMapper.TypeHandler<DateTime?>
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
					: DateTime.FromBinary( (long)value );
	}

	private static readonly NullableDateTimeTypeHandler instance = new ();

	public static NullableDateTimeTypeHandler Instance => instance;
}