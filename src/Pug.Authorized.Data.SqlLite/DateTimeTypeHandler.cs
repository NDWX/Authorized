using System.Data;
using Dapper;

namespace Pug.Authorize.Data.SqlLite;

internal class DateTimeTypeHandler : SqlMapper.TypeHandler<DateTime>
{
	public override void SetValue( IDbDataParameter parameter, DateTime value )
	{
		long ticks = value.ToUniversalTime().Ticks;

		parameter.Value = ticks;
	}

	public override DateTime Parse( object value )
	{
		return DateTime.FromBinary( (long)value );
	}

	private static readonly DateTimeTypeHandler instance = new ();

	public static DateTimeTypeHandler Instance => instance;
}