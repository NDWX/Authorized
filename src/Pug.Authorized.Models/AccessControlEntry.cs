using System.ComponentModel.DataAnnotations;
using System.Runtime.Serialization;
using Pug.Effable;

namespace Pug.Authorized;

public record AccessControlEntry : Identifiable<string>
{
	[Required]
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

	[Required]
	[DataMember(IsRequired = true)]
	public AccessControlEntryDefinition Definition
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
	public ActionContext<Reference> Registration
	{
		get;
#if NET5_0_OR_GREATER
		init;
#else
		set;
#endif
	}

	[Required]
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