/// The "iss" (issuer) claim identifies the principal that issued the
/// JWT.  The processing of this claim is generally application specific.
/// The "iss" value is a case-sensitive string containing a StringOrURI
/// value.  Use of this claim is OPTIONAL.
public struct IssuerClaim: JWTClaim, Equatable, ExpressibleByStringLiteral {
    /// See ``JWTClaim``.
    public var value: String

    /// See ``JWTClaim``.
    public init(value: String) {
        self.value = value
    }
}
