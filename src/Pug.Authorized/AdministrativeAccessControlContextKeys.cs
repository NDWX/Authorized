namespace Pug.Authorized;

public static class AdministrativeAccessControlContextKeys
{
	public static readonly string
		SubjectType = "SUBJECT.TYPE",
		SubjectIdentifier = "SUBJECT.IDENTIFIER",
		ObjectType = "OBJECT.TYPE",
		ObjectIdentifier = "OBJECT.IDENTIFIER",
		Purpose = "PURPOSE",
		ObjectDomain = "OBJECT.DOMAIN";
}