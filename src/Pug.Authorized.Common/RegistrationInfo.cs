using System;
using System.Runtime.Serialization;

namespace Pug.Authorized
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