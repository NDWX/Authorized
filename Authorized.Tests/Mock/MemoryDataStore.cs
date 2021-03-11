using System.Collections.Generic;
using System.Data;
using System.Linq;
using Authorized.Data;

namespace Authorized.Tests
{
	class MemoryDataStore : IAuthorizedDataStore
	{
		private List< ObjectAccessControlEntry> _accessControlEntries =
			new List< ObjectAccessControlEntry>()
			{
				/*new ObjectAccessControlEntry()
				{
					Identifier = "0",
					Object = new AccessControlledObject()
					{
						Domain = string.Empty,
						Purpose = string.Empty,
						Object = new Noun()
						{
							Type = "OBJECT",
							Identifier = "DEFAULT"
						}
					},
					AccessControlEntry = new AccessControlEntry()
					{
						Identifier = "0",
						Subject = new Noun()
						{
							Type = SubjectTypes.User,
							Identifier = "user"
						},
						Action = AdministrativeActions.ManagePermissions,
						Context = new List<AccessControlContextEntry>() {},
						Permission = Permission.Allowed
					}
				},*/
				new ObjectAccessControlEntry()
				{
					Identifier = "1",
					Object = new AccessControlledObject()
					{
						Domain = string.Empty,
						Purpose = string.Empty,
						Object = new Noun()
						{
							Type = "OBJECT",
							Identifier = "DEFAULT"
						}
					},
					AccessControlEntry = new AccessControlEntry()
					{
						Identifier = "1",
						Subject = new Noun()
						{
							Type = SubjectTypes.User,
							Identifier = "administrator"
						},
						Action = AdministrativeActions.ManagePermissions,
						Context = new List<AccessControlContextEntry>() {},
						Permission = Permission.Allowed
					}
				},
				new ObjectAccessControlEntry()
				{
					Identifier = "2",
					Object = new AccessControlledObject()
					{
						Domain = string.Empty,
						Purpose = string.Empty,
						Object = new Noun()
						{
							Type = "OBJECT",
							Identifier = "DEFAULT"
						}
					},
					AccessControlEntry = new AccessControlEntry()
					{
						Identifier = "2",
						Subject = new Noun()
						{
							Type = SubjectTypes.Group,
							Identifier = "USERS"
						},
						Action = AdministrativeActions.ViewPermissions,
						Context = new List<AccessControlContextEntry>() {},
						Permission = Permission.Allowed
					}
				},
				new ObjectAccessControlEntry()
				{
					Identifier = "3",
					Object = new AccessControlledObject()
					{
						Domain = string.Empty,
						Purpose = string.Empty,
						Object = new Noun()
						{
							Type = "OBJECT",
							Identifier = "DEFAULT"
						}
					},
					AccessControlEntry = new AccessControlEntry()
					{
						Identifier = "3",
						Subject = new Noun()
						{
							Type = SubjectTypes.User,
							Identifier = "adminuser"
						},
						Action = AdministrativeActions.ManagePermissions,
						Context = new List<AccessControlContextEntry>() {},
						Permission = Permission.Allowed
					}
				},
				new ObjectAccessControlEntry()
				{
					Identifier = "4",
					Object = new AccessControlledObject()
					{
						Domain = string.Empty,
						Purpose = string.Empty,
						Object = new Noun()
						{
							Type = "OBJECT",
							Identifier = "DEFAULT"
						}
					},
					AccessControlEntry = new AccessControlEntry()
					{
						Identifier = "4",
						Subject = new Noun()
						{
							Type = SubjectTypes.Group,
							Identifier = "POWERUSERS"
						},
						Action = AdministrativeActions.ManagePermissions,
						Context = new List<AccessControlContextEntry>() {},
						Permission = Permission.Denied
					}
				},
				new ObjectAccessControlEntry()
				{
					Identifier = "5",
					Object = new AccessControlledObject()
					{
						Domain = string.Empty,
						Purpose = string.Empty,
						Object = new Noun()
						{
							Type = "OBJECT",
							Identifier = "DEFAULT"
						}
					},
					AccessControlEntry = new AccessControlEntry()
					{
						Identifier = "5",
						Subject = new Noun()
						{
							Type = SubjectTypes.Group,
							Identifier = "SYSADMINS"
						},
						Action = AdministrativeActions.ManagePermissions,
						Context = new List<AccessControlContextEntry>() {},
						Permission = Permission.Allowed
					}
				}
			};

		public void Dispose()
		{
		}

		public void BeginTransaction()
		{
		}

		public void BeginTransaction(IsolationLevel isolationLevel)
		{
		}

		public void CommitTransaction()
		{
		}

		public void RollbackTransaction()
		{
		}

		public IEnumerable<AccessControlEntry> GetAccessControlEntries(Noun subject, string action, Noun @object, string purpose, string domain)
		{
			IEnumerable<ObjectAccessControlEntry> objectAccessControlEntries = _accessControlEntries
				.Where(x => 
							x.Object.Domain == domain &&
							x.Object.Purpose == purpose &&
							x.Object.Object == @object &&
							x.AccessControlEntry.Subject == subject &&
							x.AccessControlEntry.Action == action);
			
			return objectAccessControlEntries
										.Select(x => x.AccessControlEntry);
		}

		public void DeleteAccessControlEntries(Noun @object, Noun subject)
		{
		}

		public bool AccessControlEntryExists(string identifier)
		{
			return false;
		}

		public void InsertAccessControlEntry(string domain, string purpose, Noun @object, AccessControlEntry entry)
		{
			// if(_accessControlEntries.ContainsKey(entry.Identifier))
			// 	throw new Exception("Duplicate access control entry identifier");
			//
			// AccessControlledObject obj = new AccessControlledObject()
			// {
			// 	Domain = domain,
			// 	Purpose = purpose,
			// 	Object = @object
			// };
			//
			// _accessControlEntries[entry.Identifier] = new ObjectAccessControlEntry()
			// {
			// 	Identifier = entry.Identifier, Object = obj, AccessControlEntry = entry
			// };
		}
	}
}