/// The "azp" (authorized party) claim identifies the party that is authorized to use the token.
/// This claim is only needed when the ID Token has a single audience value and that audience is
/// different than the authorized party. It MAY be included even when the authorized party is
/// the same as the sole audience. The azp value is a case sensitive string containing a StringOrURI value.
public struct AuthorizedPartyClaim: JWTClaim, Equatable, ExpressibleByStringLiteral {
    /// See ``JWTClaim``.
    public var value: String
    
    /// See ``JWTClaim``.
    public init(value: String) {
        self.value = value
    }
    
    /// Verifies that the authorized party matches the expected client ID.
    ///
    /// - Parameter clientId: The expected client ID.
    /// - Throws: ``JWTError/claimVerificationFailure`` if the authorized party does not match the expected client ID.
    public func verify(clientId: String) throws {
        guard value == clientId else {
            throw JWTError.claimVerificationFailure(
                failedClaim: self,
                reason: "Authorized party '\(value)' does not match expected client ID '\(clientId)'"
            )
        }
    }
}