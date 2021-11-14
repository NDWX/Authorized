using System;
using System.Runtime.Serialization;

namespace Pug.Authorized
{
	[Serializable]
	public class DuplicateIdentifierException : Exception
	{
		private const string DUPLICATED_IDENTIFIER_FIELD = "duplicatedIdentifier";
		public string Identifier { get; }

		protected DuplicateIdentifierException(SerializationInfo info, StreamingContext context) : base(info, context)
		{
			Identifier = info.GetString(DUPLICATED_IDENTIFIER_FIELD);
		}

		public DuplicateIdentifierException(string identifier)
		{
			Identifier = identifier;
		}

		public override void GetObjectData(SerializationInfo info, StreamingContext context)
		{
			base.GetObjectData(info, context);
			
			info.AddValue(DUPLICATED_IDENTIFIER_FIELD, Identifier);
		}
	}
}