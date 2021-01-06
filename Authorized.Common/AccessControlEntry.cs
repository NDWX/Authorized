using System.Collections.Generic;
using System.Runtime.Serialization;
using Pug.Effable;

namespace Authorized
{
	public class AccessControlEntry : Identifiable<string>
	{
		public string Identifier { get; set; }
		
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
		[DataMember(IsRequired = true)]
		public IEnumerable<AccessControlContextEntry> Context { get; set; }

		[DataMember(IsRequired = true)]
		public Permission Permission { get; set; }
		
		[DataMember]
		public RegistrationInfo RegistrationInfo { get; set; }
	}
}