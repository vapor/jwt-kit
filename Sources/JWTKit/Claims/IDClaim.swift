/// The "jti" (JWT ID) claim provides a unique identifier for the JWT.
/// The identifier value MUST be assigned in a manner that ensures that
/// there is a negligible probability that the same value will be
/// accidentally assigned to a different data object; if the application
/// uses multiple issuers, collisions MUST be prevented among values
/// produced by different issuers as well.  The "jti" claim can be used
/// to prevent the JWT from being replayed.  The "jti" value is a case-
/// sensitive string.  Use of this claim is OPTIONAL.
public struct IDClaim: JWTClaim, Equatable, ExpressibleByStringLiteral {
    /// See ``JWTClaim``.
    public var value: String

    /// See ``JWTClaim``.
    public init(value: String) {
        self.value = value
    }
}
