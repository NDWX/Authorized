using Authorized.Data;
using Pug.Application.Data;

namespace Authorized.Tests
{
	class MemoryDataProvider : IApplicationData<IAuthorizedDataStore>
	{
		public IAuthorizedDataStore GetSession()
		{
			return new MemoryDataStore();
		}
	}
}