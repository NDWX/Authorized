using Pug.Authorized.Data;
using Pug.Application.Data;

namespace Pug.Authorized.Tests
{
	class MemoryDataProvider : IApplicationData<IAuthorizedDataStore>
	{
		public IAuthorizedDataStore GetSession()
		{
			return new MemoryDataStore();
		}
	}
}