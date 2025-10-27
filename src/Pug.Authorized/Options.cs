namespace Pug.Authorized;

public class Options
{
	public string AdministratorRole { get; set; }
		
	public string AdministrativeUser { get; set; }
		
	public string ManagementDomain { get; set; }

	public AdministrativeActionGrantees AdministrativeActionGrantees { get; set; } =
		AdministrativeActionGrantees.Administrators;
}