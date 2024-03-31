using System.Collections.Generic;
using System.Linq;

namespace Pug.Authorized;

public static class AccessControlContextExtensions
{
	// ReSharper disable once HeapView.ClosureAllocation
	public static bool Evaluate(this AccessControlContextEntry context, IEnumerable<string> values)
	{
		switch(context.MatchType)
		{
			case AccessControlContextMatchType.Equals:
				return values.Count() == 1 && context.Values.FirstOrDefault() == values.First();

			case AccessControlContextMatchType.In:
				IEnumerable<string> distinctValues = values.Distinct();
				return distinctValues.Intersect(context.Values.Distinct()).Count() == distinctValues.Count();

			case AccessControlContextMatchType.Like:
				return values.All(x => x.Contains(context.Values.First()));

			case AccessControlContextMatchType.NotEqual:
				return !values.Contains(context.Values.FirstOrDefault());

			case AccessControlContextMatchType.NotIn:
				return !values.Distinct().Intersect(context.Values.Distinct()).Any();
		}

		return false;
	}
}