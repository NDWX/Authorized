using Pug.Application.Data;
using Pug.Authorized.Data;

namespace Pug.Authorized.Tests
{
	internal class MemoryDataProvider : IApplicationData<IAuthorizedDataStore>
	{
		public IAuthorizedDataStore GetSession()
		{
			return new MemoryDataStore();
		}
	}
}