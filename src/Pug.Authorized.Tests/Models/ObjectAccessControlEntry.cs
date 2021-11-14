namespace Pug.Authorized.Tests
{
	internal class ObjectAccessControlEntry
	{
		public string Identifier { get; set; }
		
		public AccessControlledObject Object { get; set; }
		
		public AccessControlEntry AccessControlEntry { get; set; }
	}
}