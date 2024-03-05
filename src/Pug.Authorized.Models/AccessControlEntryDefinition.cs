using System.Collections.Generic;
using System.Runtime.Serialization;

namespace Pug.Authorized;

public record AccessControlEntryDefinition
{
	[DataMember(IsRequired = true)]
	public string Action
	{
		get;
#if NET6_0_OR_GREATER
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
#if NET6_0_OR_GREATER
		init;
#else
			set;
#endif
	}

	[DataMember(IsRequired = true)]
	public Permissions Permissions
	{
		get;
#if NET6_0_OR_GREATER
		init;
#else
			set;
#endif
	}
}