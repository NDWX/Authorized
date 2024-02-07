using System.Runtime.Serialization;

namespace Pug.Authorized
{
	public sealed record Noun
	{
		[DataMember(IsRequired = true)]
		public string Type
		{
			get;
#if NET6_0_OR_GREATER
			init;
#else
			set;
#endif
		}
		
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
	}
}