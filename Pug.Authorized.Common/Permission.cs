using System;
using System.Runtime.Serialization;

namespace Pug.Authorized
{
	[DataContract]
	[Flags]
	public enum Permission
	{
		[EnumMember]
		None = 0,
		[EnumMember]
		Denied = 1,
		[EnumMember]
		Allowed = 2,
		[EnumMember]
		Grant = 6
	}
}