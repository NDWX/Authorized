namespace Pug.Authorized.Tests
{
	class AccessControlledObject
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
}