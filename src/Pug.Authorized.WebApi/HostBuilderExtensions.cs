using Microsoft.Extensions.DependencyInjection;

namespace Pug.Authorized.Rest;

public static class HostBuilderExtensions
{
	public static IServiceCollection AddAuthorizationWebApiHandler( this IServiceCollection serviceCollection )
	{
		serviceCollection.AddSingleton<WebApiHandler>( 
			sp => new WebApiHandler( sp.GetRequiredService<IAuthorized>() )
		);

		return serviceCollection;
	}
}