using System.Collections.Generic;
using System.Runtime.Serialization;
using Pug.Effable;

namespace Pug.Authorized
{
	public class AccessControlEntry : Identifiable<string>
	{
		public string Identifier { get; set; }
		
		[DataMember(IsRequired = true)]
		public Noun Subject { get; set; }

		[DataMember(IsRequired = true)]
		public string Action { get; set; }
		
		/// <summary>
		/// Exact match
		/// </summary>
		[DataMember(IsRequired = true)]
		public IEnumerable<AccessControlContextEntry> Context { get; set; }

		[DataMember(IsRequired = true)]
		public Permissions Permissions { get; set; }
		
		[DataMember]
		public RegistrationInfo RegistrationInfo { get; set; }
	}
}