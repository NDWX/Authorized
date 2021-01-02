namespace Authorized
{
	public class Options
	{
		public string AdministratorGroup { get; set; }
		
		public string AdministrativeUser { get; set; }

		public AdministrativeActionGrantees AdministrativeActionGrantees { get; set; } =
			AdministrativeActionGrantees.Administrators;
	}
}