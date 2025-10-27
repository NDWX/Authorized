using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Http;
using Microsoft.Extensions.DependencyInjection;

namespace Pug.Authorized.Rest;

public static class WebApplicationExtensions
{
	private static RouteHandlerBuilder Document( this RouteHandlerBuilder routeHandlerBuilder, string name )
	{
		return routeHandlerBuilder 
			.WithName( name )
			.WithTags( "Authorizations" )
#if NET8_0_OR_GREATER
			.WithOpenApi()
#endif
			;
	}
	
	public static WebApplication MapAuthorizationApis( this WebApplication webApplication,
														string basePath = "/authorizations" )
	{
		basePath = basePath.TrimEnd( '/' );
		basePath = basePath.StartsWith( '/' ) ? basePath : $"/{basePath}";

		WebApiHandler? webApiHandler = webApplication.Services.GetService<WebApiHandler>();

		if( webApiHandler is null )
			return webApplication;
		
		webApplication.MapGet(
							$"{basePath}/domains/{{domain}}/{{purpose}}/objects/{{objectType}}/{{objectIdentifier}}/effectivePermission",
							webApiHandler.GetEffectivePermissionAsync
						)
					.RequireAuthorization()
					.Document( nameof(webApiHandler.GetEffectivePermissionAsync) );

		webApplication.MapGet(
							$"{basePath}/domains/{{domain}}/{{purpose}}/objects/{{objectType}}/{{objectIdentifier}}/accessControlLists",
							webApiHandler.GetAccessControlListsAsync
						)
					.RequireAuthorization()
					.Document( nameof(webApiHandler.GetAccessControlListsAsync) );

		webApplication.MapGet(
							$"{basePath}/domains/{{domain}}/{{purpose}}/objects/{{objectType}}/{{objectIdentifier}}/accessControlLists/subjects/{{subjectType}}/{{subjectIdentifier}}",
							webApiHandler.GetAccessControlEntriesAsync
						)
					.RequireAuthorization()
					.Document( nameof(webApiHandler.GetAccessControlEntriesAsync) );

		webApplication.MapPost(
							$"{basePath}/domains/{{domain}}/{{purpose}}/objects/{{objectType}}/{{objectIdentifier}}/accessControlLists/subjects/{{subjectType}}/{{subjectIdentifier}}",
							webApiHandler.SetSubjectAccessControlEntries
						)
					.RequireAuthorization()
					.Document( nameof(webApiHandler.SetSubjectAccessControlEntries) );
		
		webApplication.MapPost(
							$"{basePath}/domains/{{domain}}/{{purpose}}/objects/{{objectType}}/{{objectIdentifier}}/accessControlLists/",
							webApiHandler.SetAccessControlListsAsync
						)
					.RequireAuthorization()
					.Document( nameof(webApiHandler.SetAccessControlListsAsync) );

		return webApplication;
	}
}