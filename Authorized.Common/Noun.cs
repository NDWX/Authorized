using System.Runtime.Serialization;

namespace Authorized
{
	public class Noun
	{
		[DataMember(IsRequired = true)]
		public string Type { get; set; }
		
		[DataMember(IsRequired = true)]
		public string Identifier { get; set; }
	}
}