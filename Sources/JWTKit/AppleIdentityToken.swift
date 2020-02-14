/// - See Also:
/// [Retrieve the User’s Information from Apple ID Servers](https://developer.apple.com/documentation/signinwithapplerestapi/authenticating_users_with_sign_in_with_apple)
public struct AppleIdentityToken: JWTPayload {
    enum CodingKeys: String, CodingKey {
        case iss, aud, exp, iat, sub, nonce, email
        case emailVerified = "email_verified"
    }

    /// The issuer-registered claim key, which has the value https://appleid.apple.com.
    public let iss: IssuerClaim

    /// Your `client_id` in your Apple Developer account.
    public let aud: AudienceClaim

    /// The expiry time for the token. This value is typically set to 5 minutes.
    public let exp: ExpirationClaim

    /// The time the token was issued.
    public let iat: IssuedAtClaim

    /// The unique identifier for the user.
    public let sub: SubjectClaim

    /// A string value used to associate a client session and an ID token. This value is used to mitigate replay attacks and is present only if passed during the authorization request.
    public let nonce: String?

    /// The user's email address.
    public let email: String?

    /// A Boolean value that indicates whether the service has verified the email. The value of this claim is always true because the servers only return verified email addresses.
    public let emailVerified: BoolClaim?

    public func verify(using signer: JWTSigner) throws {
        guard self.iss.value == "https://appleid.apple.com" else {
            throw JWTError.claimVerificationFailure(name: "iss", reason: "Token not provided by Apple")
        }

        try exp.verifyNotExpired()
    }
}
