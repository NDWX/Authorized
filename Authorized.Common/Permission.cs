﻿using System.Runtime.Serialization;

namespace Authorized
{
	[DataContract]
	public enum Permission
	{
		[EnumMember]
		None = -1,
		[EnumMember]
		Denied = 0,
		[EnumMember]
		Allowed = 1,
		[EnumMember]
		Grant = 3
	}
}