/// The "sub" (subject) claim identifies the principal that is the
/// subject of the JWT. The claims in a JWT are normally statements
/// about the subject. The subject value MUST either be scoped to be
/// locally unique in the context of the issuer or be globally unique.
/// The processing of this claim is generally application specific.  The
/// "sub" value is a case-sensitive string containing a StringOrURI
/// value. Use of this claim is OPTIONAL.
public struct SubjectClaim: JWTClaim, Equatable, ExpressibleByStringLiteral {
    /// See ``JWTClaim``.
    public var value: String

    /// See ``JWTClaim``.
    public init(value: String) {
        self.value = value
    }
}
