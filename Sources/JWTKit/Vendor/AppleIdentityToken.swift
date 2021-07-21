/// - See Also:
/// [Retrieve the User’s Information from Apple ID Servers](https://developer.apple.com/documentation/signinwithapplerestapi/authenticating_users_with_sign_in_with_apple)
public struct AppleIdentityToken: JWTPayload {
    enum CodingKeys: String, CodingKey {
        case nonce, email
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case issuedAt = "iat"
        case expires = "exp"
        case emailVerified = "email_verified"
        case isPrivateEmail = "is_private_email"
        case nonceSupported = "nonce_supported"
    }

    /// The issuer-registered claim key, which has the value https://appleid.apple.com.
    public let issuer: IssuerClaim

    /// Your `client_id` in your Apple Developer account.
    public let audience: AudienceClaim

    /// The expiry time for the token. This value is typically set to 5 minutes.
    public let expires: ExpirationClaim

    /// The time the token was issued.
    public let issuedAt: IssuedAtClaim

    /// The unique identifier for the user.
    public let subject: SubjectClaim

    /// A Boolean value that indicates whether the transaction is on a nonce-supported platform. If you sent a nonce in the authorization
    /// request but do not see the nonce claim in the ID token, check this claim to determine how to proceed. If this claim returns true you
    /// should treat nonce as mandatory and fail the transaction; otherwise, you can proceed treating the nonce as optional.
    public let nonceSupported: BoolClaim?

    /// A string value used to associate a client session and an ID token. This value is used to mitigate replay attacks and is present only
    /// if passed during the authorization request.
    public let nonce: String?

    /// The user's email address.
    public let email: String?

    /// A Boolean value that indicates whether the service has verified the email. The value of this claim is always true because the servers only return verified email addresses.
    public let emailVerified: BoolClaim?
    
    /// A Boolean value that indicates whether the email shared by the user is the proxy address. It is absent (nil) if the user is not using a proxy email address.
    public let isPrivateEmail: BoolClaim?

    public func verify(using signer: JWTSigner) throws {
        guard self.issuer.value == "https://appleid.apple.com" else {
            throw JWTError.claimVerificationFailure(name: "iss", reason: "Token not provided by Apple")
        }

        try self.expires.verifyNotExpired()
    }
}
