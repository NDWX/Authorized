using System.ComponentModel.DataAnnotations;
using System.Runtime.Serialization;

namespace Pug.Authorized;

public sealed record Noun
{
	[Required( AllowEmptyStrings = true)]
	[DataMember(IsRequired = true)]
	public string Type
	{
		get;
#if NET5_0_OR_GREATER
		init;
#else
			set;
#endif
	}
		
	[Required( AllowEmptyStrings = true)]
	[DataMember(IsRequired = true)]
	public string Identifier
	{
		get;
#if NET5_0_OR_GREATER
		init;
#else
			set;
#endif
	}
}