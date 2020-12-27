using System.Collections.Generic;

namespace Authorized
{
	public class AccessControlContextEntry
	{
		public string Key { get; set; }
		
		public AccessControlContextMatchType  MatchType { get; set; }
		
		public IEnumerable<string> Values { get; set; }
	}
}