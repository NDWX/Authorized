using System;
using System.Collections.Generic;
using System.Threading.Tasks;
using Pug.Application.Security;

namespace Pug.Authorized;

public interface IAuthorized
{
	[Obsolete("Use overload with NounQualifier for @object instead")]
	Task<Permissions> IsAuthorizedAsync(Noun subject, string action, DomainObject @object, IDictionary<string, IEnumerable<string>> context,
										string purpose);

	Task<Permissions> IsAuthorizedAsync(Noun subject, string action, NounQualifier @object, IDictionary<string, IEnumerable<string>> context,
										string purpose);

	[Obsolete("Use overload with NounQualifier for @object instead")]
	Task<IEnumerable<AccessControlEntry>> GetAccessControlEntriesAsync(
		string purpose, DomainObject @object, Noun subject);
	
	Task<IEnumerable<AccessControlEntry>> GetAccessControlEntriesAsync(
		string purpose, NounQualifier @object, Noun subject);

	[Obsolete("Use overload with NounQualifier for @object instead")]
	Task<IDictionary<Noun, IEnumerable<AccessControlEntry>>> GetAccessControlListsAsync(
		string purpose, DomainObject @object);
	
	Task<IDictionary<Noun, IEnumerable<AccessControlEntry>>> GetAccessControlListsAsync(
		string purpose, NounQualifier @object);

	[Obsolete("Use overload with NounQualifier for @object instead")]
	Task SetAccessControlEntriesAsync(string purpose, DomainObject @object, Noun subject,
									IEnumerable<AccessControlEntryDefinition> entries);
	
	Task SetAccessControlEntriesAsync(string purpose, NounQualifier @object, Noun subject,
									IEnumerable<AccessControlEntryDefinition> entries);

	[Obsolete("Use overload with NounQualifier for @object instead")]
	Task SetAccessControlListsAsync(string purpose, DomainObject @object, IDictionary<Noun, IEnumerable<AccessControlEntryDefinition>> accessControlLists);
	
	Task SetAccessControlListsAsync(string purpose, NounQualifier @object, IDictionary<Noun, IEnumerable<AccessControlEntryDefinition>> accessControlLists);
}