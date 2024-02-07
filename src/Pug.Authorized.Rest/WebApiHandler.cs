using System.ComponentModel.DataAnnotations;
using Microsoft.AspNetCore.Mvc;

namespace Pug.Authorized.Rest;

public class WebApiHandler
{
	private readonly IAuthorized _authorized;

	public WebApiHandler( IAuthorized authorized )
	{
		_authorized = authorized;
	}
	
	[ProducesResponseType(StatusCodes.Status401Unauthorized)]
	[ProducesResponseType(StatusCodes.Status403Forbidden)]
	[ProducesResponseType(typeof(Permissions), StatusCodes.Status200OK)]
	public async Task<IResult> GetEffectivePermissionAsync( [Required, FromRoute] string domain,
														[Required, FromRoute] string purpose,
														[Required, FromRoute] string objectType,
														[Required, FromRoute] string objectIdentifier,
														[Required, FromQuery] string subjectType,
														[Required, FromQuery] string subjectIdentifier,
														[Required, FromQuery] string action )
	{
		Permissions permission = await _authorized.IsAuthorizedAsync(
									new Noun()
									{
										Type = subjectType,
										Identifier = subjectIdentifier
									},
									action,
									new DomainObject()
									{
										Domain = domain,
										Object = new Noun()
										{
											Type = objectType,
											Identifier = objectIdentifier
										}
									},
									null,
									purpose );

#if NET8_0
		return TypedResults.Ok( permission );
#else
		return Results.Ok( permission );
#endif
	}
	
	[ProducesResponseType(StatusCodes.Status401Unauthorized)]
	[ProducesResponseType(StatusCodes.Status403Forbidden)]
	[ProducesResponseType( typeof(IDictionary<Noun, IEnumerable<AccessControlEntry>>), StatusCodes.Status200OK)]
	public async Task<IResult> GetAccessControlListsAsync( [Required, FromRoute] string domain,
															[Required, FromRoute] string purpose,
															[Required, FromRoute] string objectType,
															[Required, FromRoute] string objectIdentifier)
	{
		IDictionary<Noun, IEnumerable<AccessControlEntry>>? accessControlLists =
			await _authorized.GetAccessControlListsAsync(
				purpose,
				new DomainObject()
				{
					Domain = domain,
					Object = new Noun() { Type = objectType, Identifier = objectIdentifier }
				});

#if NET8_0
		return TypedResults.Ok( accessControlLists );
#else
		return Results.Ok( accessControlLists );
#endif
	}
	
	[ProducesResponseType(StatusCodes.Status401Unauthorized)]
	[ProducesResponseType(StatusCodes.Status403Forbidden)]
	[ProducesResponseType( typeof(IEnumerable<AccessControlEntry>), StatusCodes.Status200OK)]
	public async Task<IResult> GetAccessControlEntriesAsync( [Required, FromRoute] string domain,
														[Required, FromRoute] string purpose,
														[Required, FromRoute] string objectType,
														[Required, FromRoute] string objectIdentifier,
														[Required, FromRoute] string subjectType,
														[Required, FromRoute] string subjectIdentifier)
	{
		IEnumerable<AccessControlEntry> accessControlEntries =
			await _authorized.GetAccessControlEntriesAsync(
				purpose,
				new DomainObject()
				{
					Domain = domain,
					Object = new Noun() { Type = objectType, Identifier = objectIdentifier }
				},
				new Noun() { Type = subjectType, Identifier = subjectIdentifier } );

#if NET8_0
		return TypedResults.Ok( accessControlEntries );
#else
		return Results.Ok( accessControlEntries );
#endif
	}
	
	[ProducesResponseType(StatusCodes.Status401Unauthorized)]
	[ProducesResponseType(StatusCodes.Status403Forbidden)]
	[ProducesResponseType(StatusCodes.Status200OK)]
	public async Task<IResult> SetSubjectAccessControlEntries( [Required, FromRoute] string domain,
														[Required, FromRoute] string purpose,
														[Required, FromRoute] string objectType,
														[Required, FromRoute] string objectIdentifier,
														[Required, FromQuery] string subjectType,
														[Required, FromQuery] string subjectIdentifier,
														[Required, FromBody] IEnumerable<AccessControlEntryDefinition> accessControlEntries )
	{
		await _authorized.SetAccessControlEntriesAsync(
			purpose,
			new DomainObject()
			{
				Domain = domain,
				Object = new Noun() { Type = objectType, Identifier = objectIdentifier }
			},
			new Noun() { Type = subjectType, Identifier = subjectIdentifier },
			accessControlEntries );

#if NET8_0
		return TypedResults.Ok( );
#else
		return Results.Ok( );
#endif
	}
	
	[ProducesResponseType(StatusCodes.Status401Unauthorized)]
	[ProducesResponseType(StatusCodes.Status403Forbidden)]
	[ProducesResponseType(StatusCodes.Status200OK)]
	public async Task<IResult> SetAccessControlListsAsync( [Required, FromRoute] string domain,
																[Required, FromRoute] string purpose,
																[Required, FromRoute] string objectType,
																[Required, FromRoute] string objectIdentifier,
																[Required, FromBody] IDictionary<Noun, IEnumerable<AccessControlEntryDefinition>> accessControlLists )
	{
		await _authorized.SetAccessControlListsAsync(
			purpose,
			new DomainObject()
			{
				Domain = domain,
				Object = new Noun() { Type = objectType, Identifier = objectIdentifier }
			},
			accessControlLists );

#if NET8_0
		return TypedResults.Ok( );
#else
		return Results.Ok( );
#endif
	}
}