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
public struct AudienceClaim: JWTMultiValueClaim, Equatable, ExpressibleByStringLiteral {
    /// See ``JWTClaim``.
    public var value: [String]

    /// See ``JWTClaim``.
    public init(value: [String]) {
        precondition(!value.isEmpty, "An audience claim must have at least one audience.")
        self.value = value
    }

    /// See `ExpressibleByStringLiteral`.
    public init(stringLiteral value: String) {
        self.init(value: value)
    }

    /// Verify that the given audience is included as one of the claim's
    /// intended audiences by simple string comparison.
    public func verifyIntendedAudience(includes audience: String) throws {
        guard self.value.contains(audience) else {
            throw JWTError.claimVerificationFailure(failedClaim: self, reason: "not intended for \(audience)")
        }
    }
}
