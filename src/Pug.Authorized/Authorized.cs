using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Pug.Authorized.Data;
using Pug.Application.Data;
using Pug.Application.Security;
using Pug.Effable;
using Pug.Lang;

namespace Pug.Authorized;

public class Authorized : IAuthorized
{
	private readonly IApplicationData<IAuthorizedDataStore> _dataStoreProvider;
	private readonly Options _options;
	private readonly IdentifierGenerator _identifierGenerator;
	private readonly ISessionUserIdentityAccessor _sessionUserIdentityAccessor;
	private readonly IUserRoleProvider _userRoleProvider;

	public Authorized( Options options, IdentifierGenerator identifierGenerator,
						ISessionUserIdentityAccessor sessionUserIdentityAccessor,
						IUserRoleProvider userRoleProvider,
						IApplicationData<IAuthorizedDataStore> dataStoreProvider )
	{
		_dataStoreProvider = dataStoreProvider ?? throw new ArgumentNullException( nameof(dataStoreProvider) );
		_options = options ?? throw new ArgumentNullException( nameof(options) );
		_identifierGenerator = identifierGenerator;
		_sessionUserIdentityAccessor = sessionUserIdentityAccessor ??
										throw new ArgumentNullException( nameof(sessionUserIdentityAccessor) );
		_userRoleProvider = userRoleProvider ?? throw new ArgumentNullException( nameof(userRoleProvider) );
	}

	private bool UserIsAdministrator()
	{
		IPrincipalIdentity principalIdentity = _sessionUserIdentityAccessor.GetUserIdentity();

		return principalIdentity.Identifier == _options.AdministrativeUser ||
				_userRoleProvider.UserIsInRole( principalIdentity.Identifier,
												_options.AdministratorRole );
	}

	private Noun GetCurrentSubject()
	{
		Noun authorizationSubject = new ()
		{
			Identifier = _sessionUserIdentityAccessor.GetUserIdentity().Identifier, Type = SubjectTypes.User
		};

		return authorizationSubject;
	}

	/// <summary>
	/// Get lowest permission level granted to specified <paramref name="subject"/> for <paramref name="action"/> on specified <paramref name="object"/>
	/// </summary>
	/// <param name="subject"></param>
	/// <param name="action"></param>
	/// <param name="object"></param>
	/// <param name="context"></param>
	/// <param name="purpose"></param>
	/// <param name="dataStore"></param>
	/// <returns>Lowest permission level granted to specified <paramref name="subject"/> for <paramref name="action"/> on specified <paramref name="object"/></returns>
	private static async Task<Permissions> GetPermissionAsync( Noun subject, string action, DomainObject @object,
																IDictionary<string, IEnumerable<string>> context,
																string purpose,
																IAuthorizedDataStore dataStore )
	{
		// get object access control entries
		IEnumerable<AccessControlEntry> accessControlEntries =
			await dataStore.GetAccessControlEntriesAsync( purpose, @object, subject, action )
							.ConfigureAwait( false );

		if( !( accessControlEntries?.Any() ?? false ) )
			return Permissions.None;

		Permissions permissions = Permissions.None;

		foreach( AccessControlEntry accessControlEntry in accessControlEntries )
		{
			bool contextMatched =
				accessControlEntry.Definition.Context.All(
						contextEntry => context.ContainsKey( contextEntry.Key ) &&
										contextEntry.Evaluate( context[contextEntry.Key] )
					);

			if( !contextMatched )
				continue;

			if( accessControlEntry.Definition.Permissions == Permissions.Denied )
				return Permissions.Denied;

			if( permissions < accessControlEntry.Definition.Permissions )
				permissions = accessControlEntry.Definition.Permissions;
		}

		return permissions;
	}

	/// <summary>
	/// Get effective <paramref name="action"/> permission granted to <paramref name="subject"/> for:
	/// <list type="bullet">
	///		<item>
	///			<term>Specified <paramref name="object"/>: </term>
	///			<description>If specific permission has been granted to user for <paramref name="object"/></description>
	///		</item>
	///		<item>
	///			<term>Specified <paramref name="object"/> type: </term>
	///			<description>If no specific permission has been granted to user for <paramref name="object"/></description>
	///		</item>
	/// </list>
	///
	/// </summary>
	/// <param name="subject"></param>
	/// <param name="action"></param>
	/// <param name="object"></param>
	/// <param name="context"></param>
	/// <param name="purpose"></param>
	/// <param name="dataSession"></param>
	/// <returns>
	/// <list type="bullet">
	///		<listheader>
	///			<term>Permission for</term>
	///			<description>Condition</description>
	///		</listheader>
	///		<item>
	///			<term>Specified <paramref name="object"/>: </term>
	///			<description>If specific permission has been granted to user for <paramref name="object"/></description>
	///		</item>
	///		<item>
	///			<term>Specified <paramref name="object"/> type: </term>
	///			<description>If no specific permission has been granted to user for <paramref name="object"/></description>
	///		</item>
	/// </list>
	/// </returns>
	private async Task<Permissions> GetEffectivePermissionAsync( Noun subject, string action, DomainObject @object,
																IDictionary<string, IEnumerable<string>> context,
																string purpose,
																IAuthorizedDataStore dataSession )
	{
		// check authorization for specified parameters
		Permissions permissions =
			await GetPermissionAsync( subject, action, @object, context, purpose, dataSession )
				.ConfigureAwait( false );

		if( permissions != Permissions.None )
			return permissions;

		// check permission for 'action' against entire object 'type' rather than specific object
		if( @object != null && !string.IsNullOrWhiteSpace( @object.Object.Type ) )
		{
			// check authorization for object type
			if( !string.IsNullOrWhiteSpace( @object.Object.Identifier ) )
			{
				permissions =
					await GetPermissionAsync( subject, action,
											@object with
											{
												Object = @object.Object with { Identifier = string.Empty }
											},
											context, purpose, dataSession );

				if( permissions != Permissions.None )
					return permissions;
			}

			// check authorization for action
			permissions =
				await GetPermissionAsync( subject, action,
										@object with { Object = null }, context,
										purpose, dataSession );

			if( permissions != Permissions.None )
				return permissions;

		}

		return Permissions.None;
	}

	/// <summary>
	/// Determine accumulated effective <paramref name="action"/> permission for <paramref name="action"/> on <paramref name="object"/> granted to <paramref name="roles"/>
	/// </summary>
	/// <param name="roles"></param>
	/// <param name="action"></param>
	/// <param name="object"></param>
	/// <param name="context"></param>
	/// <param name="purpose"></param>
	/// <param name="dataStore"></param>
	/// <returns>
	/// Accumulated effective <paramref name="action"/> permission for <paramref name="action"/> on <paramref name="object"/> granted to <paramref name="roles"/>
	/// </returns>
	private async Task<Permissions> GetEffectivePermissionAsync( IEnumerable<string> roles, string action,
																DomainObject @object,
																IDictionary<string, IEnumerable<string>> context,
																string purpose, IAuthorizedDataStore dataStore )
	{
		Permissions permissions = Permissions.None;

		Permissions effectivePermissions = permissions;

		// check authorization for each role
		foreach( string role in roles )
		{
			permissions = await GetEffectivePermissionAsync(
							new Noun() { Identifier = role, Type = SubjectTypes.Group },
							action, @object, context, purpose, dataStore );

			if( permissions == Permissions.Denied )
				return Permissions.Denied;

			effectivePermissions |= permissions;
		}

		return effectivePermissions;
	}

	/// <summary>
	/// Determine effective <paramref name="action"/> permission for <paramref name="action"/> on <paramref name="object"/> granted to either <paramref name="subject" /> or it's effective <paramref name="effectiveRoles"/>
	/// </summary>
	/// <param name="subject"></param>
	/// <param name="effectiveRoles"></param>
	/// <param name="action"></param>
	/// <param name="object"></param>
	/// <param name="context"></param>
	/// <param name="purpose"></param>
	/// <param name="dataSession"></param>
	/// <returns>
	/// Accumulated effective <paramref name="action"/> permission for <paramref name="action"/> on <paramref name="object"/> granted to <paramref name="effectiveRoles"/>
	/// </returns>
	private async Task<Permissions> GetEffectivePermissionAsync( Noun subject, IEnumerable<string> effectiveRoles,
																string action,
																DomainObject @object,
																IDictionary<string, IEnumerable<string>> context,
																string purpose, IAuthorizedDataStore dataSession )
	{
		// check authorization for user
		Permissions permissions = await GetEffectivePermissionAsync( subject, action, @object, context,
																	purpose, dataSession );

		if( permissions == Permissions.Denied )
			return Permissions.Denied;

		Permissions effectivePermissions = permissions;

		// Evaluate effective roles authorization
		effectivePermissions |=
			await GetEffectivePermissionAsync( effectiveRoles, action, @object, context, purpose, dataSession );

		if( effectivePermissions == Permissions.Denied || subject.Type == SubjectTypes.Group ||
			@object.Domain == _options.ManagementDomain )
			return effectivePermissions;

		IEnumerable<string> managementRoles =
			_userRoleProvider.GetUserRoles( subject.Identifier, _options.ManagementDomain );

		if( !managementRoles.Any() )
			return effectivePermissions;

		effectivePermissions |=
			await GetEffectivePermissionAsync( managementRoles, action, @object, context, purpose, dataSession );

		return effectivePermissions;
	}

	private Task CheckSetAceAuthorizationAsync( string purpose, DomainObject @object,
												Dictionary<string, IEnumerable<string>> authorizationContext,
												Noun authorizationSubject )
	{
		return _dataStoreProvider.PerformAsync(
				async ( dataSession, ctx ) =>
				{
					bool allowed = false;

					Permissions effectivePermissions = await ctx.@this.GetEffectivePermissionAsync(
															ctx.authorizationSubject,
															ctx.@this._userRoleProvider.GetUserRoles(
																ctx.authorizationSubject.Identifier,
																ctx.@object.Domain ),
															AdministrativeActions.ManagePermissions,
															ctx.@object,
															ctx.authorizationContext,
															ctx.purpose,
															dataSession );

					allowed =
						( // users with permissions are allowed to manage permissions
							effectivePermissions == Permissions.Allowed
						) ||
						( ctx.@this.UserIsAdministrator() && effectivePermissions != Permissions.Denied );


					if( !allowed )
						throw new NotAuthorized();
				},
				new
				{
					@this = this,
					@object = @object, purpose, authorizationContext,
					authorizationSubject
				}
			);
	}

	private static Dictionary<string, IEnumerable<string>> PopulateAdministratorAuthorizationContext(
		string purpose, DomainObject @object, Noun subject = null )
	{
		Dictionary<string, IEnumerable<string>> authorizationContext = new ()
		{
			[AdministrativeAccessControlContextKeys.ObjectType] = new[] { @object.Object.Type },
			[AdministrativeAccessControlContextKeys.ObjectIdentifier] = new[] { @object.Object.Identifier },
			[AdministrativeAccessControlContextKeys.ObjectDomain] = new[] { @object.Domain },
			[AdministrativeAccessControlContextKeys.Purpose] = new[] { purpose },
		};

		if( subject is not null )
		{
			authorizationContext[AdministrativeAccessControlContextKeys.SubjectType] = new[] { subject.Type };
			authorizationContext[AdministrativeAccessControlContextKeys.SubjectIdentifier] =
				new[] { subject.Identifier };
		}

		return authorizationContext;
	}

	public Task<Permissions> IsAuthorizedAsync( Noun subject, string action, DomainObject @object,
												IDictionary<string, IEnumerable<string>> context, string purpose )
	{
		Validate( purpose, @object, false, false, subject );

		action.Validate();

		IEnumerable<string> effectiveRoles = null;

		if( subject.Type != SubjectTypes.Group )
			effectiveRoles = _userRoleProvider.GetUserRoles( subject.Identifier, @object.Domain );

		return _dataStoreProvider.ExecuteAsync(
				async ( dataSession, ctx ) =>
				{
					Permissions effectivePermission =
						await ctx.@this.GetEffectivePermissionAsync( ctx.subject, ctx.effectiveRoles, ctx.action,
																	ctx.@object, ctx.context, ctx.purpose,
																	dataSession );

					return effectivePermission ==
							Permissions.Allowed
								? Permissions.Allowed
								: Permissions.Denied;
				},
				new { @this = this, subject, action, @object = @object, context, purpose, effectiveRoles }
			);
	}

	public Task<Permissions> IsAuthorizedAsync( Noun subject, IEnumerable<string> effectiveRoles, string action,
												DomainObject @object,
												IDictionary<string, IEnumerable<string>> context, string purpose )
	{
		Validate( purpose, @object, false, false, subject );

		if( effectiveRoles == null ) throw new ArgumentNullException( nameof(effectiveRoles) );

		return _dataStoreProvider.ExecuteAsync(
				async ( dataSession, ctx ) =>
				{
					Permissions effectivePermissions =
						await ctx.@this.GetEffectivePermissionAsync( ctx.subject, ctx.effectiveRoles, ctx.action,
																	ctx.@object, ctx.context, ctx.purpose,
																	dataSession );

					if( effectivePermissions == Permissions.Denied )
						return effectivePermissions;

					return ( effectivePermissions & Permissions.Allowed ) == Permissions.Allowed
								? Permissions.Allowed
								: Permissions.Denied;
				},
				new { @this = this, subject, effectiveRoles, action, @object, context, purpose }
			);
	}

	private static OneOf<Unit, PossibleErrors<ArgumentException, ArgumentNullException>> Validate(
		string purpose, DomainObject @object, bool objectRequired, bool objectIdentifierRequired)
	{
		if( string.IsNullOrWhiteSpace( purpose ) )
			return new PossibleErrors<ArgumentException, ArgumentNullException>(
					new ArgumentException( "Value cannot be null or whitespace.", nameof(purpose) )
				);

		if( @object is null )
			return new PossibleErrors<ArgumentException, ArgumentNullException>(
					new ArgumentNullException( nameof(@object) )
				);

		OneOf<Unit, PossibleErrors<ArgumentException, ArgumentNullException>> result =
			@object.Validate(objectRequired, objectIdentifierRequired );

		if( result.Is<PossibleErrors<ArgumentException, ArgumentNullException>>() )
			return result.Second;

		return Unit.Value;
	}

	private static OneOf<Unit, PossibleErrors<ArgumentException, ArgumentNullException>> Validate(
		string purpose, DomainObject @object, bool objectRequired, bool objectIdentifierRequired, Noun subject)
	{
		OneOf<Unit, PossibleErrors<ArgumentException, ArgumentNullException>> result =
			Validate( purpose, @object, objectRequired, objectIdentifierRequired );

		if( !result.Is<Unit>() )
			return result.Second;

		if( subject is null )
			return new PossibleErrors<ArgumentException, ArgumentNullException>(
					new ArgumentNullException( nameof(subject) )
				);

		result = subject.Validate( nameof(subject) );

		if( !result.Is<Unit>() )
			return result.Second;

		return Unit.Value;
	}

	public async Task<IEnumerable<AccessControlEntry>> GetAccessControlEntriesAsync(
		string purpose, DomainObject @object, Noun subject )
	{
		Validate( purpose, @object, false, false, subject );

		Dictionary<string, IEnumerable<string>> authorizationContext =
			PopulateAdministratorAuthorizationContext( purpose, @object, subject );

		Noun authorizationSubject = GetCurrentSubject();

		return await _dataStoreProvider.ExecuteAsync(
						async ( dataSession, ctx ) =>
						{
							bool allowed = false;

							switch( ctx.@this._options.AdministrativeActionGrantees )
							{
								case AdministrativeActionGrantees.Administrators:

									allowed = ctx.@this.UserIsAdministrator();

									break;

								case AdministrativeActionGrantees.AllowedUsers:

									Permissions effectivePermissions = await ctx.@this.GetEffectivePermissionAsync(
																			ctx.authorizationSubject,
																			ctx.@this._userRoleProvider
																				.GetUserRoles(
																					ctx.authorizationSubject
																						.Identifier,
																					ctx.@object.Domain ),
																			AdministrativeActions.ViewPermissions,
																			ctx.@object,
																			ctx.authorizationContext,
																			ctx.purpose,
																			dataSession );

									allowed =
										( // users with permissions are allowed to manage permissions
											effectivePermissions == Permissions.Allowed
										) ||
										( ctx.@this.UserIsAdministrator() &&
										effectivePermissions != Permissions.Denied );

									break;

								case AdministrativeActionGrantees.Subject:

									allowed = ctx.subject != null &&
											ctx.subject.Type == SubjectTypes.User &&
											!string.IsNullOrEmpty( ctx.subject.Identifier ) &&
											ctx.authorizationSubject.Identifier ==
											ctx.subject.Identifier;

									break;
							}

							if( !allowed )
							{
								throw new NotAuthorized();
							}

							return await dataSession.GetAccessControlEntriesAsync(
										ctx.purpose, ctx.@object, ctx.subject );
						},
						new
						{
							@this = this, subject, @object = @object, purpose, authorizationContext,
							authorizationSubject
						}
					);
	}

	public async Task<IDictionary<Noun, IEnumerable<AccessControlEntry>>> GetAccessControlListsAsync( string purpose, DomainObject @object )
	{
		Validate( purpose, @object, false, false );

		Dictionary<string, IEnumerable<string>> authorizationContext =
			PopulateAdministratorAuthorizationContext( purpose, @object );

		Noun authorizationSubject = GetCurrentSubject();

		return await _dataStoreProvider.ExecuteAsync(
						async ( dataSession, ctx ) =>
						{
							bool allowed = false;

							switch( ctx.@this._options.AdministrativeActionGrantees )
							{
								case AdministrativeActionGrantees.Administrators:

									allowed = ctx.@this.UserIsAdministrator();

									break;

								case AdministrativeActionGrantees.AllowedUsers:

									Permissions effectivePermissions = await ctx.@this.GetEffectivePermissionAsync(
																			ctx.authorizationSubject,
																			ctx.@this._userRoleProvider
																				.GetUserRoles(
																					ctx.authorizationSubject
																						.Identifier,
																					ctx.@object.Domain ),
																			AdministrativeActions.ViewPermissions,
																			ctx.@object,
																			ctx.authorizationContext,
																			ctx.purpose,
																			dataSession );

									allowed =
										( // users with permissions are allowed to manage permissions
											effectivePermissions == Permissions.Allowed
										) ||
										( ctx.@this.UserIsAdministrator() &&
										effectivePermissions != Permissions.Denied );

									break;

								case AdministrativeActionGrantees.Subject:

									allowed = false;

									break;
							}

							if( !allowed )
							{
								throw new NotAuthorized();
							}

							return await dataSession.GetAccessControlListsAsync(
										ctx.purpose, ctx.@object );
						},
						new
						{
							@this = this, @object, purpose, authorizationContext,
							authorizationSubject
						}
					);
	}

	private static async Task Insert( AccessControlEntryDefinition entry, string purpose, DomainObject @object,
									Noun subject, IAuthorizedDataStore dataStore, IdentifierGenerator idGenerator,
									IPrincipalIdentity principal )
	{
		string identifier = idGenerator.GetNext();

		if( await dataStore.AccessControlEntryExistsAsync( identifier ) )
			throw new DuplicateIdentifierException( "Identifier generator returned duplicated key." );

		AccessControlEntry ace = new ()
		{
			Identifier = identifier,
			Definition = entry,
			Registration = new ActionContext()
			{
				Timestamp = DateTime.UtcNow,
				Actor = new Reference()
				{
					Type = "USER",
					Identifier = principal.Identifier
				}
			}
		};

		await dataStore.InsertAsync( purpose, @object, subject, ace );
	}

	private static async Task SetAccessControlEntries( string purpose, DomainObject @object, Noun subject,
														IEnumerable<AccessControlEntryDefinition> entries,
														IAuthorizedDataStore dataSession,
														IPrincipalIdentity currentUser,
														IdentifierGenerator identifierGenerator )
	{
		IEnumerable<AccessControlEntry> existingEntries =
			await dataSession.GetAccessControlEntriesAsync( purpose, @object, subject );

		await dataSession.DeleteAccessControlEntriesAsync( purpose, @object, subject );

		foreach( AccessControlEntryDefinition definition in entries )
		{
			AccessControlEntry existingEntry =
				existingEntries.FirstOrDefault(
						x =>
							x.Definition.Action == definition.Action &&
							x.Definition.Permissions == definition.Permissions
					);

			if( existingEntry is null )
			{
				await Insert( definition, purpose, @object, subject, dataSession, identifierGenerator,
							currentUser );
			}
			else
			{
				await dataSession.InsertAsync( purpose, @object, subject,
												existingEntry with
												{
													Definition = definition,
													LastUpdate = new ActionContext()
													{
														Actor = new Reference()
														{
															Type = "USER",
															Identifier = currentUser.Identifier
														},
														Timestamp = DateTime.UtcNow
													}
												} );
			}
		}
	}

	public async Task SetAccessControlEntriesAsync( string purpose, DomainObject @object, Noun subject,
													IEnumerable<AccessControlEntryDefinition> entries )
	{
		Validate( purpose, @object, false, false, subject);

		// ReSharper disable once PossibleMultipleEnumeration
		foreach( AccessControlEntryDefinition entry in entries )
		{
			entry.Validate( nameof(entries) );
		}

		Dictionary<string, IEnumerable<string>> authorizationContext =
			PopulateAdministratorAuthorizationContext( purpose, @object, null );

		Noun authorizationSubject = GetCurrentSubject();

		// ReSharper disable once PossibleMultipleEnumeration
		await CheckSetAceAuthorizationAsync( purpose, @object, authorizationContext,
											authorizationSubject );

		await _dataStoreProvider.PerformAsync(
				async ( dataSession, ctx ) =>
				{
					await SetAccessControlEntries( ctx.purpose, ctx.@object, ctx.subject, ctx.entries, dataSession,
													ctx.@this._sessionUserIdentityAccessor.GetUserIdentity(),
													ctx.@this._identifierGenerator );
				},
				new
				{
					@this = this, @object, purpose, subject, entries, authorizationContext, authorizationSubject
				}
			);
	}

	public async Task SetAccessControlListsAsync( string purpose, DomainObject @object,
												IDictionary<Noun, IEnumerable<AccessControlEntryDefinition>> accessControlLists )
	{
		Validate( purpose, @object, false, false );

		foreach( KeyValuePair<Noun,IEnumerable<AccessControlEntryDefinition>> list in accessControlLists )
		{
			list.Key.ValidateSpecification( "subject" );

			// ReSharper disable once PossibleMultipleEnumeration
			foreach( AccessControlEntryDefinition entry in list.Value )
			{
				entry.Validate( nameof(accessControlLists) );
			}
		}

		Dictionary<string, IEnumerable<string>> authorizationContext =
			PopulateAdministratorAuthorizationContext( purpose, @object, null );

		Noun authorizationSubject = GetCurrentSubject();

		// ReSharper disable once PossibleMultipleEnumeration
		await CheckSetAceAuthorizationAsync( purpose, @object, authorizationContext,
											authorizationSubject );

		await _dataStoreProvider.PerformAsync(
				async ( dataSession, ctx ) =>
				{
					foreach( KeyValuePair<Noun, IEnumerable<AccessControlEntryDefinition>> list in
							ctx.accessControlLists )
					{
						await SetAccessControlEntries( ctx.purpose, ctx.@object, list.Key, list.Value, dataSession,
														ctx.@this._sessionUserIdentityAccessor.GetUserIdentity(),
														ctx.@this._identifierGenerator );
					}
				},
				new
				{
					@this = this, @object, purpose, accessControlLists = accessControlLists, authorizationContext, authorizationSubject
				}
			);
	}
}