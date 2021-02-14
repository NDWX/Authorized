using System;
using System.Runtime.Serialization;

namespace Authorized
{
	public class Noun : IEquatable<Noun>
	{
		[DataMember(IsRequired = true)]
		public string Type { get; set; }
		
		[DataMember(IsRequired = true)]
		public string Identifier { get; set; }

		public bool Equals(Noun other)
		{
			if(ReferenceEquals(null, other)) return false;
			if(ReferenceEquals(this, other)) return true;
			return Type == other.Type && Identifier == other.Identifier;
		}

		public override bool Equals(object obj)
		{
			if(ReferenceEquals(null, obj)) return false;
			if(ReferenceEquals(this, obj)) return true;
			if(obj.GetType() != this.GetType()) return false;
			return Equals((Noun) obj);
		}

		public override int GetHashCode()
		{
			unchecked
			{
				return ((Type != null ? Type.GetHashCode() : 0) * 397) ^ (Identifier != null ? Identifier.GetHashCode() : 0);
			}
		}

		public static bool operator ==(Noun left, Noun right)
		{
			return Equals(left, right);
		}

		public static bool operator !=(Noun left, Noun right)
		{
			return !Equals(left, right);
		}
	}
}