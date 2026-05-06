using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Runtime.Serialization;

namespace Pug.Authorized;

[DataContract]
public record AccessControlContextEntry
{
	[Required]
	[DataMember( IsRequired = true )]
	public string Key
	{
		get;
#if NET5_0_OR_GREATER
		init;
#else
			set;
#endif
	}

	[Required]
	[DataMember(IsRequired = true)]
	public AccessControlContextMatchType  MatchType
	{
		get;
#if NET5_0_OR_GREATER
		init;
#else
			set;
#endif
	}
		
	[Required]
	[DataMember(IsRequired = true)]
	public IEnumerable<string> Values
	{
		get;
#if NET5_0_OR_GREATER
		init;
#else
			set;
#endif
	}
}