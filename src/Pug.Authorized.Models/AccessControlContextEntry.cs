using System.Collections.Generic;
using System.Runtime.Serialization;

namespace Pug.Authorized;

[DataContract]
public record AccessControlContextEntry
{
	[DataMember( IsRequired = true )]
	public string Key
	{
		get;
#if NET6_0_OR_GREATER
		init;
#else
			set;
#endif
	}

	[DataMember(IsRequired = true)]
	public AccessControlContextMatchType  MatchType
	{
		get;
#if NET6_0_OR_GREATER
		init;
#else
			set;
#endif
	}
		
	[DataMember(IsRequired = true)]
	public IEnumerable<string> Values
	{
		get;
#if NET6_0_OR_GREATER
		init;
#else
			set;
#endif
	}
}