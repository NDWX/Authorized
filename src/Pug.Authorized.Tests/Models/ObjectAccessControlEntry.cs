namespace Pug.Authorized.Tests
{
	class ObjectAccessControlEntry
	{
		public string Identifier { get; set; }
		
		public AccessControlledObject @Object { get; set; }
		
		public AccessControlEntry AccessControlEntry { get; set; }
	}
}