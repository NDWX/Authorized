using System.Collections.Generic;
using System.Runtime.Serialization;

namespace Authorized
{
	public class AccessControlEntry
	{
		/*
		[DataMember(IsRequired = true)]
		public string Domain { get; set; }
		
		[DataMember(IsRequired = true)]
		public string Purpose { get; set; }
		*/

		[DataMember(IsRequired = true)]
		public Noun Subject { get; set; }

		[DataMember(IsRequired = true)]
		public string Action { get; set; }
		
		// public Noun Object { get; set; }
		
		/// <summary>
		/// Exact match
		/// </summary>
		public IEnumerable<AccessControlContextEntry> Context { get; set; }
		
		[DataMember(IsRequired = true)]
		public Permission Permission { get; set; }
	}
}