using System;

namespace Pug.Authorized
{
	[Flags]
	public enum AdministrativeActionGrantees
	{
		/// <summary>
		/// Default
		/// </summary>
		Administrators = 1,
		/// <summary>
		/// Subjects are allowed to view their own access control entries
		/// </summary>
		Subject = 2,
		/// <summary>
		/// Administrators and users with permissions are allowed to view or manage access control entries
		/// </summary>
		AllowedUsers = 4
	}
}