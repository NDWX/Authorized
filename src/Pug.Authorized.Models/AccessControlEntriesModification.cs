using System.Runtime.Serialization;

namespace Pug.Authorized
{
	[DataContract]
	public enum AccessControlEntriesModification
	{
		[EnumMember]
		Append = 1,
		[EnumMember]
		Replace = 2,
		[EnumMember]
		Remove = 4
	}
}