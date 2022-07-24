using System.Collections.Generic;
using System.Threading.Tasks;

namespace Pug.Authorized
{
	public interface IAuthorized
	{
		Permissions IsAuthorized(Noun subject, string action, DomainObject @object, IDictionary<string, IEnumerable<string>> context,
								string purpose);

		Permissions IsAuthorized(Noun subject, IEnumerable<string> effectiveRoles, string action, DomainObject @object,
								IDictionary<string, IEnumerable<string>> context, string purpose);
								
		Task<Permissions> IsAuthorizedAsync(Noun subject, string action, DomainObject @object, IDictionary<string, IEnumerable<string>> context,
											string purpose);

		Task<Permissions> IsAuthorizedAsync(Noun subject, IEnumerable<string> effectiveRoles, string action, DomainObject @object,
								IDictionary<string, IEnumerable<string>> context, string purpose);

		IEnumerable<AccessControlEntry> GetAccessControlEntries(Noun subject, string purpose, DomainObject @object);

		Task<IEnumerable<AccessControlEntry>> GetAccessControlEntriesAsync(Noun subject, string purpose, DomainObject @object);

		void SetAccessControlEntries(string purpose, DomainObject @object,
									IEnumerable<AccessControlEntry> entries, Noun subject = null);

		Task SetAccessControlEntriesAsync(string purpose, DomainObject @object,
									IEnumerable<AccessControlEntry> entries, Noun subject = null);
	}
}