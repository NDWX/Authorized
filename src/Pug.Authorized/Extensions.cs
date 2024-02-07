using System;
using Pug.Lang;

namespace Pug.Authorized
{
	public static class ModelExtensions
	{
		public static OneOf<Unit, PossibleErrors<ArgumentException, ArgumentNullException>> Validate(
			this Noun subject, string parameterName, bool identifierRequired = true )
		{
			if( subject == null )
				return new PossibleErrors<ArgumentException, ArgumentNullException>(
						new ArgumentNullException( parameterName )
					);

			if( string.IsNullOrWhiteSpace( subject.Type ) )
				return new PossibleErrors<ArgumentException, ArgumentNullException>(
						new ArgumentException( ExceptionMessages.SUBJECT_TYPE_MUST_BE_SPECIFIED, parameterName )
					);

			if( identifierRequired && string.IsNullOrWhiteSpace( subject.Identifier ) )
				return new PossibleErrors<ArgumentException, ArgumentNullException>(
						new ArgumentException( ExceptionMessages.SUBJECT_IDENTIFIER_MUST_BE_SPECIFIED, parameterName )
					);

			return Unit.Value;
		}

		public static OneOf<Unit, PossibleErrors<ArgumentException, ArgumentNullException>> Validate(this  DomainObject @object, bool objectRequired , bool identifierRequired = true)
		{
			if( @object == null )
				return new PossibleErrors<ArgumentException, ArgumentNullException>(
						new ArgumentNullException( nameof(@object) )
					);
			
			if( objectRequired && @object.Object == null ) 
				return new PossibleErrors<ArgumentException,ArgumentNullException>(
						new ArgumentNullException( $"{nameof(@object)}.{nameof(@object.Object)}" )
					);
			
			OneOf<Unit, PossibleErrors<ArgumentException, ArgumentNullException>> result = 
				@object.Object?.Validate("@object.Object", identifierRequired );

			if( result is not null && !result.Is<Unit>() )
				return result.Second;

			return Unit.Value;
		}
		
		public static void Validate( this string action )
		{
			if( string.IsNullOrWhiteSpace( action ) )
				throw new ArgumentException( ExceptionMessages.VALUE_CANNOT_BE_NULL_OR_WHITESPACE, nameof(action) );
		}

		public static void Validate(this AccessControlEntryDefinition entry, string parameterName)
		{
			if(string.IsNullOrEmpty(entry.Action))
				throw new ArgumentException(ExceptionMessages.ACE_ACTION_MUST_BE_SPECIFIED, parameterName);
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