namespace Pug.Authorized;

public record DomainObject
{
	public string Domain
	{
		get;
#if NET6_0_OR_GREATER
		init;
#else
			set;
#endif
	}
		
	public Noun Object
	{
		get;
#if NET6_0_OR_GREATER
		init;
#else
			set;
#endif
	}
}