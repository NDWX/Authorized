using System.Linq;

namespace Authorized.Extensions
{
	public static class AccessControlContextExtensions
	{
		public static bool Evaluate(this AccessControlContextEntry context, string value)
		{
			switch(context.MatchType)
			{
				case AccessControlContextMatchType.Equals:
					return context.Values.FirstOrDefault() == value;

				case AccessControlContextMatchType.In:
					return context.Values.Contains(value);

				case AccessControlContextMatchType.Like:
					return value.Contains(context.Values.First());

				case AccessControlContextMatchType.NotEqual:
					return context.Values.FirstOrDefault() != value;

				case AccessControlContextMatchType.NotIn:
					return !context.Values.Contains(value);
			}
			
			return false;
		}
	}
}