using Microsoft.Extensions.DependencyInjection;
using Pug.Application.Data;
using Pug.Application.Security;
using Pug.Authorized.Data;

namespace Pug.Authorized.DependencyInjection;

// ReSharper disable once UnusedType.Global
public static class IServiceCollectionExtensions
{
	public static IServiceCollection AddAuthorized(
		this IServiceCollection serviceCollection, Options options, IdentifierGenerator identifierGenerator
	)
	{
		serviceCollection.AddSingleton( provider =>
			{
				IPrincipalIdentityAccessor? principalIdentityAccessor =
					provider.GetService<IPrincipalIdentityAccessor>();
				
				if( principalIdentityAccessor is null )
					principalIdentityAccessor =
					provider.GetService<ISessionUserIdentityAccessor>();
				
				if( principalIdentityAccessor is null )
					throw new InvalidOperationException( "Principal identity accessor is not registered" );

				IPrincipalRoleProvider? userRoleProvider =
					provider.GetService<IPrincipalRoleProvider>();

				if( userRoleProvider is null )
				{
					IUserRoleProvider? roleProvider = provider.GetService<IUserRoleProvider>();
					
					if( roleProvider is null )
						throw new InvalidOperationException( "Principal role provider is not registered" );
					
					userRoleProvider = new UserRoleProviderAdapter( roleProvider );
				}

				IApplicationData<IAuthorizedDataStore>? applicationData =
					provider.GetService<IApplicationData<IAuthorizedDataStore>>();

				return new Authorized(
					options,
					identifierGenerator,
					principalIdentityAccessor,
					userRoleProvider,
					applicationData
				);

			}
		);

		return serviceCollection;
	}
}