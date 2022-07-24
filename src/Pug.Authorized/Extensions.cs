using System;

namespace Pug.Authorized
{
	public static class ModelExtensions
	{
		public static void Validate( this Noun subject, string parameterName, bool identifierRequired = true )
		{
			if(subject == null) throw new ArgumentNullException(parameterName);

			if( string.IsNullOrWhiteSpace( subject.Type ) )
				throw new ArgumentException( ExceptionMessages.SUBJECT_TYPE_MUST_BE_SPECIFIED, parameterName );

			if( identifierRequired && string.IsNullOrWhiteSpace( subject.Identifier ) )
				throw new ArgumentException( ExceptionMessages.SUBJECT_IDENTIFIER_MUST_BE_SPECIFIED, parameterName );
		}
		
		public static void Validate(this  DomainObject @object, bool objectRequired , bool identifierRequired = true)
		{
			if( @object == null ) throw new ArgumentNullException( nameof(@object) );
			
			if( objectRequired && @object.Object == null ) 
				throw new ArgumentNullException( $"{nameof(@object)}.{nameof(@object.Object)}" );
			
			@object.Object?.Validate("@object.Object", identifierRequired );
		}
		
		public static void Validate( this string action )
		{
			if( string.IsNullOrWhiteSpace( action ) )
				throw new ArgumentException( ExceptionMessages.VALUE_CANNOT_BE_NULL_OR_WHITESPACE, nameof(action) );
		}

		public static void ValidateSubjectSpecification(this AccessControlEntry entry, string parameterName)
		{
			if(entry.Subject == null)
			{
				throw new ArgumentException(ExceptionMessages.ACE_SUBJECT_MUST_BE_SPECIFIED, parameterName);
			}

			if(string.IsNullOrEmpty(entry.Subject.Type))
				throw new ArgumentException(ExceptionMessages.ACE_SUBJECT_TYPE_MUST_BE_SPECIFIED, parameterName);

			if(string.IsNullOrWhiteSpace(entry.Subject.Identifier))
				throw new ArgumentException(ExceptionMessages.ACE_SUBJECT_IDENTIFIER_MUST_BE_SPECIFIED, parameterName);
		}

		public static void ValidateSpecification(this Noun subject, string parameterName)
		{
			if(string.IsNullOrWhiteSpace(subject.Type))
				throw new ArgumentException(ExceptionMessages.SUBJECT_TYPE_MUST_BE_SPECIFIED, parameterName);

			if(string.IsNullOrWhiteSpace(subject.Identifier))
				throw new ArgumentException(ExceptionMessages.SUBJECT_IDENTIFIER_MUST_BE_SPECIFIED, parameterName);
		}
	}
}