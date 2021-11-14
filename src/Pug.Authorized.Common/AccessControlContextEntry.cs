using System.Collections.Generic;
using System.Runtime.Serialization;

namespace Pug.Authorized
{
	[DataContract]
	public class AccessControlContextEntry
	{
		[DataMember(IsRequired = true)]
		public string Key { get; set; }
		
		[DataMember(IsRequired = true)]
		public AccessControlContextMatchType  MatchType { get; set; }
		
		[DataMember(IsRequired = true)]
		public IEnumerable<string> Values { get; set; }
	}
}