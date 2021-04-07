using System.Collections.Generic;
using Pug.Application.Data;

namespace Pug.Authorized.Data
{
	public interface IAuthorizedDataStore : IApplicationDataSession
	{
		IEnumerable<AccessControlEntry> GetAccessControlEntries(Noun subject, string action, Noun @object,
																string purpose, string domain);

		void DeleteAccessControlEntries(Noun @object, Noun subject);

		bool AccessControlEntryExists(string identifier);

		void InsertAccessControlEntry(string domain, string purpose, Noun @object,
									AccessControlEntry entry);
	}
}