using System.Collections.Generic;

namespace Pug.Authorized
{
	public interface IAuthorized
	{
		Permissions IsAuthorized(Noun subject, string action, DomainObject @object, IDictionary<string, IEnumerable<string>> context,
								string purpose);

		Permissions IsAuthorized(Noun subject, IEnumerable<string> effectiveRoles, string action, DomainObject @object,
								IDictionary<string, IEnumerable<string>> context, string purpose);

		IEnumerable<AccessControlEntry> GetAccessControlEntries(Noun subject, string purpose, DomainObject @object);

		void SetAccessControlEntries(string purpose, DomainObject @object,
									IEnumerable<AccessControlEntry> entries, Noun subject = null);
	}
}