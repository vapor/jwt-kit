/// The "aud" (audience) claim identifies the recipients that the JWT is
/// intended for.  Each principal intended to process the JWT MUST
/// identify itself with a value in the audience claim.  If the principal
/// processing the claim does not identify itself with a value in the
/// "aud" claim when this claim is present, then the JWT MUST be
/// rejected.  In the general case, the "aud" value is an array of case-
/// sensitive strings, each containing a StringOrURI value.  In the
/// special case when the JWT has one audience, the "aud" value MAY be a
/// single case-sensitive string containing a StringOrURI value.  The
/// interpretation of audience values is generally application specific.
/// Use of this claim is OPTIONAL.
public struct AudienceClaim: JWTClaim, Equatable, ExpressibleByStringLiteral {
    /// See `JWTClaim`.
    public var value: [String]

    /// See `JWTClaim`.
    public init(value: [String]) {
        precondition(!value.isEmpty, "An audience claim must have at least one audience.")
        self.value = value
    }
    
    /// Convenience for the almost universal case of only a single audience.
    public init(value: String) {
        self.init(value: [value])
    }
    
    /// See `ExpressibleByStringLiteral`.
    public init(stringLiteral value: String) {
        self.init(value: value)
    }
    
    /// Verify that the given audience is included as one of the claim's
    /// intended audiences by simple string comparison.
    public func verifyIntendedAudience(includes audience: String) throws {
        guard self.value.contains(audience) else {
            throw JWTError.claimVerificationFailure(name: "aud", reason: "not intended for \(audience)")
        }
    }

}

extension AudienceClaim {

    /// Because this claim can take either singular or plural form in JSON, the
    /// default conformance to `Decodable` from `JWTClaim` isn't good enough.
    ///
    /// - Note: The spec is mute on what an audience claim with an empty list of
    ///   audiences would be considered to represent - whether it would be the
    ///   same as having no claim at all, or represent a token intended for no
    ///   audiences whatsoever. This implementation takes the more conservative
    ///   route of simply forbidding such a representation.
    ///
    /// - Note: The spec is also mute regarding the behavior of duplicate
    ///   audiences in a list of more than one. It should probably be modeled as
    ///   a `Set` for uniqueness, but there is a theoretical use case for the
    ///   order of audiences to be a significant data point. This implementation
    ///   again takes the conservative approach of simply decoding what is there
    ///   in the order it appears, whether the values are unique or not.
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()

        do {
            self.value = [try container.decode(String.self)]
        } catch DecodingError.typeMismatch(let type, _) where type == String.self {
            self.value = try container.decode(Array<String>.self)
            
            guard !self.value.isEmpty else {
                throw DecodingError.dataCorruptedError(
                    in: container,
                    debugDescription: "An audience claim must have at least one audience.")
            }
        }
    }

    /// This claim can take either singular or plural form in JSON, with the
    /// singular being overwhelmingly more common, so when there is only one
    /// value, ensure it is encoded as a scalar, not an array.
    ///
    /// - Note: As in decoding, the implementation takes a conservative approach
    ///   with regards to the importance of ordering and the handling of
    ///   duplicate values by simply encoding what's there without further
    ///   analysis or filtering.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        
        if self.value.count == 1 {
            try container.encode(self.value[0])
        } else {
            try container.encode(self.value)
        }
    }

}
