using System;
using System.Runtime.Serialization;

namespace Authorized
{
	[DataContract]
	public class RegistrationInfo
	{
		[DataMember(IsRequired = true)]
		public string RegistrationUser { get; set; }
		
		[DataMember(IsRequired = true)]
		public DateTime RegistrationTimestamp { get; set; }
	}
}