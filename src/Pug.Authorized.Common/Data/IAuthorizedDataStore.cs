using System.Collections.Generic;
using System.Threading.Tasks;
using Pug.Application.Data;

namespace Pug.Authorized.Data
{
	public interface IAuthorizedDataStore : IApplicationDataSession
	{
		IEnumerable<AccessControlEntry> GetAccessControlEntries(Noun subject, string action, DomainObject domainObject,
																string purpose);

		void DeleteAccessControlEntries(DomainObject domainObject, Noun subject);

		bool AccessControlEntryExists(string identifier);

		void InsertAccessControlEntry(string purpose, DomainObject domainObject,
									AccessControlEntry entry);
		
		Task<IEnumerable<AccessControlEntry>> GetAccessControlEntriesAsync(Noun subject, string action, DomainObject domainObject,
																	string purpose);

		Task DeleteAccessControlEntriesAsync(DomainObject domainObject, Noun subject);

		Task<bool> AccessControlEntryExistsAsync(string identifier);

		Task InsertAccessControlEntryAsync(string purpose, DomainObject domainObject,
									AccessControlEntry entry);
	}
}