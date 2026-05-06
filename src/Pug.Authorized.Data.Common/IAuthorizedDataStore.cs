using System.Collections.Generic;
using System.Threading.Tasks;
using Pug.Application.Data;
using Pug.Application.Security;

namespace Pug.Authorized.Data
{
	public interface IAuthorizedDataStore : IApplicationDataSession
	{
		Task<IEnumerable<AccessControlEntry>> GetAccessControlEntriesAsync(
			string purpose, NounQualifier domainObject, Noun subject, string? action = null
		);

		Task<IDictionary<Noun, IEnumerable<AccessControlEntry>>> GetAccessControlListsAsync(
			string purpose, NounQualifier domainObject
		);

		Task DeleteAccessControlEntriesAsync( string purpose, NounQualifier domainObject, Noun? subject = null );

		Task<bool> AccessControlEntryExistsAsync( string identifier );

		Task InsertAsync(
			string purpose, NounQualifier domainObject, Noun subject,
			AccessControlEntry accessControlEntry
		);
	}
}