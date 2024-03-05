using System.Runtime.Serialization;
using Pug.Effable;

namespace Pug.Authorized;

public record AccessControlEntry : Identifiable<string>
{
	[DataMember(IsRequired = true)]
	public string Identifier
	{
		get;
#if NETSTANDARD2_0
			set;
#else
		init;
#endif
	}

	[DataMember(IsRequired = true)]
	public AccessControlEntryDefinition Definition
	{
		get;
#if NETSTANDARD2_0
			set;
#else
		init;
#endif
	}

	[DataMember(IsRequired = true)]
	public ActionContext Registration
	{
		get;
#if NETSTANDARD2_0
			set;
#else
		init;
#endif
	}

	[DataMember]
	public ActionContext LastUpdate
	{
		get;
#if NETSTANDARD2_0
			set;
#else
		init;
#endif
	}
}