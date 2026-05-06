using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Runtime.Serialization;

namespace Pug.Authorized;

public record AccessControlEntryDefinition
{
	[Required]
	[DataMember(IsRequired = true)]
	public string Action
	{
		get;
#if NET5_0_OR_GREATER
		init;
#else
			set;
#endif
	}

	/// <summary>
	/// Exact match
	/// </summary>
	[DataMember(IsRequired = true)]
	public IEnumerable<AccessControlContextEntry> Context
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
	public Permissions Permissions
	{
		get;
#if NET5_0_OR_GREATER
		init;
#else
			set;
#endif
	}
}