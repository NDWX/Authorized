using System.Runtime.Serialization;
using Pug.Effable;

namespace Pug.Authorized;

public record AccessControlEntry : Identifiable<string>
{
	[DataMember(IsRequired = true)]
	public string Identifier
	{
		get;
#if NET6_0_OR_GREATER
		init;
#else
		set;
#endif
	}

	[DataMember(IsRequired = true)]
	public AccessControlEntryDefinition Definition
	{
		get;
#if net5_0_or_greater
		init;
#else
		set;
#endif
	}

	[DataMember(IsRequired = true)]
	public ActionContext<Reference> Registration
	{
		get;
#if NET5_0_OR_GREATER
		init;
#else
		set;
#endif
	}

	[DataMember]
	public ActionContext<Reference> LastUpdate
	{
		get;
#if NET5_0_OR_GREATER
		init;
#else
		set;
#endif
	}
}