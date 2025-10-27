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
				ISessionUserIdentityAccessor? sessionUserIdentityAccessor =
					provider.GetService<ISessionUserIdentityAccessor>();

				IUserRoleProvider? userRoleProvider =
					provider.GetService<IUserRoleProvider>();

				IApplicationData<IAuthorizedDataStore>? applicationData =
					provider.GetService<IApplicationData<IAuthorizedDataStore>>();

				return new Authorized(
					options,
					identifierGenerator,
					sessionUserIdentityAccessor,
					userRoleProvider,
					applicationData
				);

			}
		);

		return serviceCollection;
	}
}