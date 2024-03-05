namespace Pug.Authorized.Tests;

internal class AccessControlledObject
{
	public string Domain
	{
		get;
		set;
	}

	public string Purpose
	{
		get;
		set;
	}
			
	public Noun Object { get; set; } 
}