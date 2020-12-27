using System.Collections.Generic;
using Pug.Application.Data;

namespace Authorized.Data
{
	public interface IAuthorizedDataStore : IApplicationDataSession
	{
		IEnumerable<AccessControlEntry> GetAccessControlEntries(Noun subject, string action, Noun @object,
																string purpose, string domain);
	}
}