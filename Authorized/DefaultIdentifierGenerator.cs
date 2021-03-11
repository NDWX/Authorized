using System.Globalization;
using IdGen;

namespace Authorized
{
	public class DefaultIdentifierGenerator : IdentifierGenerator
	{
		private readonly IIdGenerator<long> _generator;
		
		public DefaultIdentifierGenerator()
		{
			_generator = new IdGenerator(0, IdGeneratorOptions.Default);
		}
		
		public string GetNext()
		{
			return _generator.CreateId().ToString(CultureInfo.InvariantCulture);
		}
	}
}