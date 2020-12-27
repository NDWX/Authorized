using System.Collections;
using System.Collections.Generic;

namespace Authorized
{
	public interface IAuthorized
	{
		Permission IsAuthorized(Noun subject, string action, Noun @object, IDictionary<string, string> context,
								string purpose, string domain);

		Permission IsAuthorized(Noun subject, IEnumerable<string> effectiveRoles, string action, Noun @object,
								IDictionary<string, string> context, string purpose, string domain);

		IEnumerable<AccessControlEntry> GetAccessControlEntries(Noun subject, string purpose, Noun @object,
																string domain);

		void SetAccessControlEntries(Noun subject, string purpose, Noun @object,
									string domain, IEnumerable<AccessControlEntry> entries);
	}
}