using System.Collections.Generic;
using System.Threading.Tasks;

namespace Pug.Authorized
{
	public interface IAuthorized
	{
		Task<Permissions> IsAuthorizedAsync(Noun subject, string action, DomainObject @object, IDictionary<string, IEnumerable<string>> context,
											string purpose);

		Task<IEnumerable<AccessControlEntry>> GetAccessControlEntriesAsync(
			string purpose, DomainObject @object, Noun subject);

		Task<IDictionary<Noun, IEnumerable<AccessControlEntry>>> GetAccessControlListsAsync(
			string purpose, DomainObject @object);

		Task SetAccessControlEntriesAsync(string purpose, DomainObject @object, Noun subject,
									IEnumerable<AccessControlEntryDefinition> entries);

		Task SetAccessControlListsAsync(string purpose, DomainObject @object, IDictionary<Noun, IEnumerable<AccessControlEntryDefinition>> accessControlLists);
	}
}