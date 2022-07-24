using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using System.Transactions;
using Pug.Authorized.Data;
using Pug.Application.Data;
using Pug.Application.Security;

namespace Pug.Authorized
{
	public class Authorized : IAuthorized
	{
		private readonly IApplicationData<IAuthorizedDataStore> _dataStoreProvider;
		private readonly Options _options;
		private readonly IdentifierGenerator _identifierGenerator;
		private readonly ISessionUserIdentityAccessor _sessionUserIdentityAccessor;
		private readonly IUserRoleProvider _userRoleProvider;

		public Authorized(Options options, IdentifierGenerator identifierGenerator,
						ISessionUserIdentityAccessor sessionUserIdentityAccessor, IUserRoleProvider userRoleProvider,
						IApplicationData<IAuthorizedDataStore> dataStoreProvider)
		{
			_dataStoreProvider = dataStoreProvider ?? throw new ArgumentNullException(nameof(dataStoreProvider));
			_options = options ?? throw new ArgumentNullException(nameof(options));
			_identifierGenerator = identifierGenerator;
			_sessionUserIdentityAccessor = sessionUserIdentityAccessor ??
											throw new ArgumentNullException(nameof(sessionUserIdentityAccessor));
			_userRoleProvider = userRoleProvider ?? throw new ArgumentNullException(nameof(userRoleProvider));
		}

		private bool UserIsAdministrator()
		{
			IPrincipalIdentity principalIdentity = _sessionUserIdentityAccessor.GetUserIdentity();

			return principalIdentity.Identifier == _options.AdministrativeUser ||
					_userRoleProvider.UserIsInRole(principalIdentity.Identifier,
													_options.AdministratorRole);
		}

		private Noun GetCurrentSubject()
		{
			Noun authorizationSubject = new Noun()
			{
				Identifier = _sessionUserIdentityAccessor.GetUserIdentity().Identifier, Type = SubjectTypes.User
			};
			
			return authorizationSubject;
		}

		private Permissions GetPermission(Noun subject, string action, DomainObject @object,
										IDictionary<string, IEnumerable<string>> context, string purpose,
										IAuthorizedDataStore dataStore)
		{
			// get object access control entries
			IEnumerable<AccessControlEntry> accessControlEntries =
				dataStore.GetAccessControlEntries(subject, action, @object, purpose);

			if(!(accessControlEntries?.Any() ?? false))
				return Permissions.None;

			Permissions permissions = Permissions.None;

			foreach(AccessControlEntry accessControlEntry in accessControlEntries)
			{
				bool contextMatched = 
					accessControlEntry.Context.All( 
						contextEntry => context.ContainsKey( contextEntry.Key ) && contextEntry.Evaluate( context[contextEntry.Key] ) 
					);

				if(!contextMatched)
					continue;

				if(accessControlEntry.Permissions == Permissions.Denied)
					return Permissions.Denied;

				if(permissions < accessControlEntry.Permissions)
					permissions = accessControlEntry.Permissions;
			}

			return permissions;
		}

		private async Task<Permissions> GetPermissionAsync(Noun subject, string action, DomainObject @object,
										IDictionary<string, IEnumerable<string>> context, string purpose,
										IAuthorizedDataStore dataStore)
		{
			// get object access control entries
			IEnumerable<AccessControlEntry> accessControlEntries =
				await dataStore.GetAccessControlEntriesAsync(subject, action, @object, purpose)
								.ConfigureAwait( false );

			if(!(accessControlEntries?.Any() ?? false))
				return Permissions.None;

			Permissions permissions = Permissions.None;

			foreach(AccessControlEntry accessControlEntry in accessControlEntries)
			{
				bool contextMatched = 
					accessControlEntry.Context.All( 
							contextEntry => context.ContainsKey( contextEntry.Key ) && contextEntry.Evaluate( context[contextEntry.Key] ) 
						);

				if(!contextMatched)
					continue;

				if(accessControlEntry.Permissions == Permissions.Denied)
					return Permissions.Denied;

				if(permissions < accessControlEntry.Permissions)
					permissions = accessControlEntry.Permissions;
			}

			return permissions;
		}

		private Permissions GetEffectivePermission(Noun subject, string action, DomainObject @object,
												IDictionary<string, IEnumerable<string>> context, string purpose,
												IAuthorizedDataStore dataSession)
		{
			// check authorization for specified parameters
			Permissions permissions = GetPermission(subject, action, @object, context, purpose, dataSession);

			if(permissions != Permissions.None)
				return permissions;

			// check permission for 'action' against entire object 'type' rather than specific object
			if(@object != null && !string.IsNullOrWhiteSpace(@object.Object.Type))
			{
				DomainObject obj = new DomainObject()
				{
					Object = new Noun()
					{
						Type = @object.Object.Type,
						Identifier = @object.Object.Identifier
					},
					Domain = @object.Domain
				};

				// check authorization for object type
				if(!string.IsNullOrWhiteSpace(obj.Object.Identifier))
				{
					obj.Object.Identifier = string.Empty;

					permissions =
						GetPermission(subject, action, obj, context, purpose, dataSession);

					if(permissions != Permissions.None)
						return permissions;
				}

				// check authorization for action
				permissions =
					GetPermission(subject, action, new DomainObject() {Domain = @object.Domain, Object = null}, context, purpose, dataSession);

				if(permissions != Permissions.None)
					return permissions;

			}

			return Permissions.None;
		}

		private async Task<Permissions> GetEffectivePermissionAsync(Noun subject, string action, DomainObject @object,
													IDictionary<string, IEnumerable<string>> context, string purpose,
													IAuthorizedDataStore dataSession)
		{
			// check authorization for specified parameters
			Permissions permissions = await GetPermissionAsync(subject, action, @object, context, purpose, dataSession)
										.ConfigureAwait( false );

			if(permissions != Permissions.None)
				return permissions;

			// check permission for 'action' against entire object 'type' rather than specific object
			if(@object != null && !string.IsNullOrWhiteSpace(@object.Object.Type))
			{
				DomainObject obj = new DomainObject()
				{
					Object = new Noun()
					{
						Type = @object.Object.Type,
						Identifier = @object.Object.Identifier
					},
					Domain = @object.Domain
				};

				// check authorization for object type
				if(!string.IsNullOrWhiteSpace(obj.Object.Identifier))
				{
					obj.Object.Identifier = string.Empty;

					permissions =
						await GetPermissionAsync(subject, action, obj, context, purpose, dataSession);

					if(permissions != Permissions.None)
						return permissions;
				}

				// check authorization for action
				permissions =
					await GetPermissionAsync(subject, action, new DomainObject() {Domain = @object.Domain, Object = null}, context, purpose, dataSession);

				if(permissions != Permissions.None)
					return permissions;

			}

			return Permissions.None;
		}

		private Permissions GetEffectivePermission(IEnumerable<string> roles, string action, DomainObject @object,
													IDictionary<string, IEnumerable<string>> context,
													string purpose, IAuthorizedDataStore dataStore)
		{
			Permissions permissions = Permissions.None;
			
			Permissions effectivePermissions = permissions;

			// check authorization for each role
			foreach(string role in roles)
			{
				permissions = GetEffectivePermission(
					new Noun() {Identifier = role, Type = SubjectTypes.Group},
					action, @object, context, purpose, dataStore);

				if(permissions == Permissions.Denied)
					return Permissions.Denied;

				effectivePermissions |= permissions;
			}

			return effectivePermissions;
		}

		private async Task<Permissions> GetEffectivePermissionAsync(IEnumerable<string> roles, string action, DomainObject @object,
													IDictionary<string, IEnumerable<string>> context,
													string purpose, IAuthorizedDataStore dataStore)
		{
			Permissions permissions = Permissions.None;
			
			Permissions effectivePermissions = permissions;

			// check authorization for each role
			foreach(string role in roles)
			{
				permissions = await GetEffectivePermissionAsync(
					new Noun() {Identifier = role, Type = SubjectTypes.Group},
					action, @object, context, purpose, dataStore);

				if(permissions == Permissions.Denied)
					return Permissions.Denied;

				effectivePermissions |= permissions;
			}

			return effectivePermissions;
		}

		private Permissions GetEffectivePermission(Noun subject, IEnumerable<string> effectiveRoles, string action,
												DomainObject @object, IDictionary<string, IEnumerable<string>> context,
												string purpose, IAuthorizedDataStore dataSession)
		{
			// check authorization for user
			Permissions permissions = GetEffectivePermission(subject, action, @object, context,
															purpose, dataSession);

			if(permissions == Permissions.Denied)
				return Permissions.Denied;

			Permissions effectivePermissions = permissions;

			// Evaluate effective roles authorization
			effectivePermissions |=
				GetEffectivePermission(effectiveRoles, action, @object, context, purpose, dataSession);

			if(effectivePermissions == Permissions.Denied || subject.Type == SubjectTypes.Group || @object.Domain == _options.ManagementDomain)
				return effectivePermissions;

			IEnumerable<string> managementRoles =
				_userRoleProvider.GetUserRoles(subject.Identifier, _options.ManagementDomain);

			if(!managementRoles.Any())
				return effectivePermissions;
			
			effectivePermissions |=
				GetEffectivePermission(managementRoles, action, @object, context, purpose, dataSession);

			return effectivePermissions;
		}

		private async Task<Permissions> GetEffectivePermissionAsync(Noun subject, IEnumerable<string> effectiveRoles, string action,
													DomainObject @object, IDictionary<string, IEnumerable<string>> context,
													string purpose, IAuthorizedDataStore dataSession)
		{
			// check authorization for user
			Permissions permissions = await GetEffectivePermissionAsync(subject, action, @object, context,
															purpose, dataSession);

			if(permissions == Permissions.Denied)
				return Permissions.Denied;

			Permissions effectivePermissions = permissions;

			// Evaluate effective roles authorization
			effectivePermissions |=
				await GetEffectivePermissionAsync(effectiveRoles, action, @object, context, purpose, dataSession);

			if(effectivePermissions == Permissions.Denied || subject.Type == SubjectTypes.Group || @object.Domain == _options.ManagementDomain)
				return effectivePermissions;

			IEnumerable<string> managementRoles =
				_userRoleProvider.GetUserRoles(subject.Identifier, _options.ManagementDomain);

			if(!managementRoles.Any())
				return effectivePermissions;
			
			effectivePermissions |=
				await GetEffectivePermissionAsync(managementRoles, action, @object, context, purpose, dataSession);

			return effectivePermissions;
		}


		private void CheckSetAceAuthorization(string purpose, DomainObject @object, IEnumerable<AccessControlEntry> entries,
											Dictionary<string, IEnumerable<string>> authorizationContext, Noun authorizationSubject)
		{
			_dataStoreProvider.Perform(
					(dataSession, ctx) =>
					{
						bool allowed = false;

						switch(ctx.@this._options.AdministrativeActionGrantees)
						{
							case AdministrativeActionGrantees.Administrators:

								allowed = ctx.@this.UserIsAdministrator();

								break;

							case AdministrativeActionGrantees.AllowedUsers:

								Permissions effectivePermissions = ctx.@this.GetEffectivePermission(
									ctx.authorizationSubject,
									ctx.@this._userRoleProvider.GetUserRoles(ctx.authorizationSubject.Identifier,
																			ctx.@object.Domain),
									AdministrativeActions.ManagePermissions,
									ctx.@object,
									ctx.authorizationContext,
									ctx.purpose,
									dataSession);

								allowed =
									( // users with permissions are allowed to manage permissions
										effectivePermissions == Permissions.Allowed
									) ||
									(ctx.@this.UserIsAdministrator() && effectivePermissions != Permissions.Denied);

								break;
						}

						if(!allowed)
							throw new NotAuthorized();
					},
					new
					{
						@this = this,
						@object = @object, purpose, entries, authorizationContext,
						authorizationSubject
					},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}
		private Task CheckSetAceAuthorizationAsync(string purpose, DomainObject @object, IEnumerable<AccessControlEntry> entries,
											Dictionary<string, IEnumerable<string>> authorizationContext, Noun authorizationSubject)
		{
			return _dataStoreProvider.PerformAsync(
					async (dataSession, ctx) =>
					{
						bool allowed = false;

						switch(ctx.@this._options.AdministrativeActionGrantees)
						{
							case AdministrativeActionGrantees.Administrators:

								allowed = ctx.@this.UserIsAdministrator();

								break;

							case AdministrativeActionGrantees.AllowedUsers:

								Permissions effectivePermissions = await ctx.@this.GetEffectivePermissionAsync(
									ctx.authorizationSubject,
									ctx.@this._userRoleProvider.GetUserRoles(ctx.authorizationSubject.Identifier,
																			ctx.@object.Domain),
									AdministrativeActions.ManagePermissions,
									ctx.@object,
									ctx.authorizationContext,
									ctx.purpose,
									dataSession);

								allowed =
									( // users with permissions are allowed to manage permissions
										effectivePermissions == Permissions.Allowed
									) ||
									(ctx.@this.UserIsAdministrator() && effectivePermissions != Permissions.Denied);

								break;
						}

						if(!allowed)
							throw new NotAuthorized();
					},
					new
					{
						@this = this,
						@object = @object, purpose, entries, authorizationContext,
						authorizationSubject
					},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}

		private static Dictionary<string, IEnumerable<string>> PopulateAdministratorAuthorizationContext(Noun subject, string purpose, DomainObject @object)
		{
			Dictionary<string, IEnumerable<string>> authorizationContext = new Dictionary<string, IEnumerable<string>>()
			{
				[AdministrativeAccessControlContextKeys.SubjectType] = new[] { subject?.Type },
				[AdministrativeAccessControlContextKeys.SubjectIdentifier] = new[] { subject?.Identifier },
				[AdministrativeAccessControlContextKeys.ObjectType] = new[] { @object.Object.Type },
				[AdministrativeAccessControlContextKeys.ObjectIdentifier] = new[] { @object.Object.Identifier },
				[AdministrativeAccessControlContextKeys.ObjectDomain] = new[] { @object.Domain },
				[AdministrativeAccessControlContextKeys.Purpose] = new[] { purpose },
			};
			
			return authorizationContext;
		}

		public Permissions IsAuthorized(Noun subject, string action, DomainObject @object, 
										IDictionary<string, IEnumerable<string>> context, string purpose)
		{
			subject.Validate(nameof(subject));
			
			action.Validate();

			@object.Validate(false);

			IEnumerable<string> effectiveRoles = null;

			if(subject.Type != SubjectTypes.Group)
				effectiveRoles = _userRoleProvider.GetUserRoles(subject.Identifier, @object.Domain);

			return _dataStoreProvider.Execute(
					(dataSession, ctx) =>
					{
						return ctx.@this.GetEffectivePermission(ctx.subject, ctx.effectiveRoles, ctx.action, ctx.@object, 
																ctx.context, ctx.purpose, dataSession) ==
								Permissions.Allowed ?
									Permissions.Allowed : Permissions.Denied;
					},
					new {@this = this, subject, action, @object = @object, context, purpose, effectiveRoles},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}
		
		public Permissions IsAuthorized(Noun subject, IEnumerable<string> effectiveRoles, string action, DomainObject @object,
										IDictionary<string, IEnumerable<string>> context,
										string purpose)
		{
			subject.Validate(nameof(subject));
			
			if(effectiveRoles == null) throw new ArgumentNullException(nameof(effectiveRoles));

			action.Validate();


			@object.Validate(false);

			return _dataStoreProvider.Execute(
					(dataSession, ctx) =>
					{
						Permissions effectivePermissions = ctx.@this.GetEffectivePermission(ctx.subject, ctx.effectiveRoles, ctx.action, 
							ctx.@object, ctx.context, ctx.purpose, dataSession);

						if(effectivePermissions == Permissions.Denied)
							return effectivePermissions;
						
						return (effectivePermissions & Permissions.Allowed) == Permissions.Allowed
									? Permissions.Allowed
									: Permissions.Denied;
					},
					new {@this = this, subject, effectiveRoles, action, @object, context, purpose},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}

		public Task<Permissions> IsAuthorizedAsync( Noun subject, string action, DomainObject @object, IDictionary<string, IEnumerable<string>> context, string purpose )
		{
			subject.Validate(nameof(subject) );
			
			action.Validate();

			@object.Validate(false);

			IEnumerable<string> effectiveRoles = null;

			if(subject.Type != SubjectTypes.Group)
				effectiveRoles = _userRoleProvider.GetUserRoles(subject.Identifier, @object.Domain);

			return _dataStoreProvider.ExecuteAsync(
					async (dataSession, ctx) =>
					{
						Permissions effectivePermission = 
							await ctx.@this.GetEffectivePermissionAsync(ctx.subject, ctx.effectiveRoles, ctx.action, 
																		ctx.@object, ctx.context, ctx.purpose, dataSession);
						
						return effectivePermission ==
								Permissions.Allowed ?
									Permissions.Allowed : Permissions.Denied;
					},
					new {@this = this, subject, action, @object = @object, context, purpose, effectiveRoles},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}

		public Task<Permissions> IsAuthorizedAsync( Noun subject, IEnumerable<string> effectiveRoles, string action, DomainObject @object, IDictionary<string, IEnumerable<string>> context, string purpose )
		{
			subject.Validate(nameof(subject));
			
			if(effectiveRoles == null) throw new ArgumentNullException(nameof(effectiveRoles));

			action.Validate();

			@object.Validate(false);

			return _dataStoreProvider.ExecuteAsync(
					async (dataSession, ctx) =>
					{
						Permissions effectivePermissions = 
							await ctx.@this.GetEffectivePermissionAsync(ctx.subject, ctx.effectiveRoles, ctx.action, 
																		ctx.@object, ctx.context, ctx.purpose, dataSession);

						if(effectivePermissions == Permissions.Denied)
							return effectivePermissions;
						
						return (effectivePermissions & Permissions.Allowed) == Permissions.Allowed
									? Permissions.Allowed
									: Permissions.Denied;
					},
					new {@this = this, subject, effectiveRoles, action, @object, context, purpose},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}
		
		public IEnumerable<AccessControlEntry> GetAccessControlEntries(Noun subject, string purpose, DomainObject @object)
		{
			subject.Validate(nameof(subject), false);
			
			@object.Validate(false);
			
			Dictionary<string, IEnumerable<string>> authorizationContext = PopulateAdministratorAuthorizationContext(subject, purpose, @object);

			Noun authorizationSubject = GetCurrentSubject();

			return _dataStoreProvider.Execute(
					(dataSession, ctx) =>
					{
						bool allowed = false;

						switch(ctx.@this._options.AdministrativeActionGrantees)
						{
							case AdministrativeActionGrantees.Administrators:
								
								allowed = ctx.@this.UserIsAdministrator();
								
								break;
							
							case AdministrativeActionGrantees.AllowedUsers:

								Permissions effectivePermissions = ctx.@this.GetEffectivePermission(
									ctx.authorizationSubject,
									ctx.@this._userRoleProvider.GetUserRoles(ctx.authorizationSubject.Identifier, ctx.@object.Domain),
									AdministrativeActions.ViewPermissions,
									ctx.@object,
									ctx.authorizationContext,
									ctx.purpose,
									dataSession);

								allowed =
									( // users with permissions are allowed to manage permissions
										effectivePermissions == Permissions.Allowed
									) ||
									(ctx.@this.UserIsAdministrator() && effectivePermissions != Permissions.Denied);
								
								break;
							
							case AdministrativeActionGrantees.Subject:
								
								allowed = ctx.subject != null &&
									ctx.subject.Type == SubjectTypes.User &&
									!string.IsNullOrEmpty(ctx.subject.Identifier) &&
									ctx.authorizationSubject.Identifier ==
									ctx.subject.Identifier;

								break;
						}
						
						if(!allowed)
						{
							throw new NotAuthorized();
						}

						return dataSession.GetAccessControlEntries(ctx.subject, string.Empty, ctx.@object, ctx.purpose);
					},
					new {@this = this, subject, @object = @object, purpose, authorizationContext, authorizationSubject},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}

		public async Task<IEnumerable<AccessControlEntry>> GetAccessControlEntriesAsync( Noun subject, string purpose, DomainObject @object )
		{
			subject.Validate(nameof(subject), false);
			
			@object.Validate(false);
			
			Dictionary<string, IEnumerable<string>> authorizationContext = PopulateAdministratorAuthorizationContext(subject, purpose, @object);

			Noun authorizationSubject = GetCurrentSubject();

			return await _dataStoreProvider.ExecuteAsync(
					async (dataSession, ctx) =>
					{
						bool allowed = false;

						switch(ctx.@this._options.AdministrativeActionGrantees)
						{
							case AdministrativeActionGrantees.Administrators:
								
								allowed = ctx.@this.UserIsAdministrator();
								
								break;
							
							case AdministrativeActionGrantees.AllowedUsers:

								Permissions effectivePermissions = await ctx.@this.GetEffectivePermissionAsync(
									ctx.authorizationSubject,
									ctx.@this._userRoleProvider.GetUserRoles(ctx.authorizationSubject.Identifier, ctx.@object.Domain),
									AdministrativeActions.ViewPermissions,
									ctx.@object,
									ctx.authorizationContext,
									ctx.purpose,
									dataSession);

								allowed =
									( // users with permissions are allowed to manage permissions
										effectivePermissions == Permissions.Allowed
									) ||
									(ctx.@this.UserIsAdministrator() && effectivePermissions != Permissions.Denied);
								
								break;
							
							case AdministrativeActionGrantees.Subject:
								
								allowed = ctx.subject != null &&
									ctx.subject.Type == SubjectTypes.User &&
									!string.IsNullOrEmpty(ctx.subject.Identifier) &&
									ctx.authorizationSubject.Identifier ==
									ctx.subject.Identifier;

								break;
						}
						
						if(!allowed)
						{
							throw new NotAuthorized();
						}

						return await dataSession.GetAccessControlEntriesAsync(ctx.subject, string.Empty, ctx.@object, ctx.purpose);
					},
					new {@this = this, subject, @object = @object, purpose, authorizationContext, authorizationSubject},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}

		public void SetAccessControlEntries(string purpose,
											DomainObject @object,
											IEnumerable<AccessControlEntry> entries, Noun subject = null)
		{
			if(subject != null)
			{
				subject.ValidateSpecification( nameof(subject));

				foreach(AccessControlEntry entry in entries)
				{
					entry.Subject = subject;
				}
			}
			else
			{
				foreach(AccessControlEntry entry in entries)
				{
					entry.ValidateSubjectSpecification(nameof(entries));
				}
			}

			@object.Validate(false, false);
			
			Dictionary<string, IEnumerable<string>> authorizationContext =
				PopulateAdministratorAuthorizationContext(subject, purpose, @object);

			Noun authorizationSubject = GetCurrentSubject();

			CheckSetAceAuthorization(purpose, @object, entries, authorizationContext, authorizationSubject);
			
			_dataStoreProvider.Perform(
					(dataSession, ctx) =>
					{
						void InsertEntries(IAuthorizedDataStore dataStore, IEnumerable<AccessControlEntry> __entries,
											string _purpose, DomainObject __object,
											IdentifierGenerator __idGenerator)
						{
							foreach(AccessControlEntry entry in __entries)
							{
								entry.Identifier = __idGenerator.GetNext();

								if(dataStore.AccessControlEntryExists(entry.Identifier))
									throw new DuplicateIdentifierException("Identifier generator returned duplicated key.");

								dataStore.InsertAccessControlEntry(_purpose, __object, entry);
							}
						}

						dataSession.DeleteAccessControlEntries(ctx.@object, ctx.subject);
						
						InsertEntries(dataSession, ctx.entries, ctx.purpose, ctx.@object,
									ctx.@this._identifierGenerator);

					},
					new
					{
						@this = this, subject,
						@object = @object, purpose, entries, authorizationContext,
						authorizationSubject
					},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}

		public async Task SetAccessControlEntriesAsync( string purpose, DomainObject @object, IEnumerable<AccessControlEntry> entries, Noun subject = null )
		{
			if(subject != null)
			{
				subject.ValidateSpecification( nameof(subject));

				foreach(AccessControlEntry entry in entries)
				{
					entry.Subject = subject;
				}
			}
			else
			{
				foreach(AccessControlEntry entry in entries)
				{
					entry.ValidateSubjectSpecification(nameof(entries));
				}
			}

			@object.Validate(false, false);
			
			Dictionary<string, IEnumerable<string>> authorizationContext =
				PopulateAdministratorAuthorizationContext(subject, purpose, @object);

			Noun authorizationSubject = GetCurrentSubject();

			await CheckSetAceAuthorizationAsync(purpose, @object, entries, authorizationContext, authorizationSubject);
			
			await _dataStoreProvider.PerformAsync(
					async (dataSession, ctx) =>
					{
						async Task InsertEntriesAsync(IAuthorizedDataStore dataStore, IEnumerable<AccessControlEntry> __entries,
											string _purpose, DomainObject __object,
											IdentifierGenerator __idGenerator)
						{
							foreach(AccessControlEntry entry in __entries)
							{
								entry.Identifier = __idGenerator.GetNext();

								if(await dataStore.AccessControlEntryExistsAsync(entry.Identifier))
									throw new DuplicateIdentifierException("Identifier generator returned duplicated key.");

								await dataStore.InsertAccessControlEntryAsync (_purpose, __object, entry);
							}
						}

						await dataSession.DeleteAccessControlEntriesAsync(ctx.@object, ctx.subject);
						
						await InsertEntriesAsync(dataSession, ctx.entries, ctx.purpose, ctx.@object,
									ctx.@this._identifierGenerator);

					},
					new
					{
						@this = this, subject, @object, purpose, entries, authorizationContext, authorizationSubject
					},
					TransactionScopeOption.Required,
					new TransactionOptions()
					{
						IsolationLevel = IsolationLevel.ReadCommitted
					}
				);
		}
	}
}