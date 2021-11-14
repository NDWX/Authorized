using System.Collections.Generic;
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
	}
}