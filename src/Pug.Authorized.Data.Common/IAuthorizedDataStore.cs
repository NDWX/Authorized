using Pug.Application.Data;

namespace Pug.Authorized.Data;

public interface IAuthorizedDataStore : IApplicationDataSession
{
	Task<IEnumerable<AccessControlEntry>> GetAccessControlEntriesAsync(
		string purpose, DomainObject domainObject, Noun subject, string action = null );

	Task<IDictionary<Noun, IEnumerable<AccessControlEntry>>> GetAccessControlListsAsync(
		string purpose, DomainObject domainObject );

	Task DeleteAccessControlEntriesAsync( string purpose, DomainObject domainObject, Noun subject = null );

	Task<bool> AccessControlEntryExistsAsync( string identifier );

	Task InsertAsync( string purpose, DomainObject domainObject, Noun subject,
					AccessControlEntry accessControlEntry );
}