/// - See Also:
/// [An ID token's payload](https://developers.google.com/identity/protocols/OpenIDConnect#an-id-tokens-payload)
public struct GoogleIdentityToken: JWTPayload {
    enum CodingKeys: String, CodingKey {
        case email, name, picture, locale, nonce, profile
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case authorizedPresenter = "azp"
        case issuedAt = "iat"
        case expires = "exp"
        case hostedDomain = "hd"
        case emailVerified = "email_verified"
        case givenName = "given_name"
        case familyName = "family_name"
        case atHash = "at_hash"
    }

    /// The Issuer Identifier for the Issuer of the response. Always https://accounts.google.com or accounts.google.com for Google ID tokens.
    public let issuer: IssuerClaim

    /// An identifier for the user, unique among all Google accounts and never reused.
    ///
    /// A Google account can have multiple email addresses at different
    /// points in time, but the sub value is never changed. Use sub within your application as the unique-identifier key for the user. Maximum length of
    /// 255 case-sensitive ASCII characters.
    public let subject: SubjectClaim

    /// The audience that this ID token is intended for. It must be one of the OAuth 2.0 client IDs of your application.
    public let audience: AudienceClaim

    /// The client_id of the authorized presenter.
    ///
    /// This claim is only needed when the party requesting the ID token is not the same as the audience of the ID token. This may be the case at
    /// Google for hybrid apps where a web application and Android app have a different OAuth 2.0 client_id but share the same Google APIs project.
    public let authorizedPresenter: String

    /// The time the ID token was issued.
    public let issuedAt: IssuedAtClaim

    /// Expiration time on or after which the ID token must not be accepted.
    public let expires: ExpirationClaim

    /// Access token hash.
    ///
    /// Provides validation that the access token is tied to the identity token. If the ID token is issued with an access_token value in
    /// the server flow, this claim is always included. This claim can be used as an alternate mechanism to protect against cross-site request forgery
    /// attacks.
    public let atHash: String?

    /// The hosted G Suite domain of the user. Provided only if the user belongs to a hosted domain.
    public let hostedDomain: GoogleHostedDomainClaim?

    /// The user's email address.
    ///
    /// This value may not be unique to this user and is not suitable for use as a primary key. Provided only if your scope included the email scope value.
    public let email: String?

    /// `True` if the user's e-mail address has been verified; otherwise `false`.
    public let emailVerified: BoolClaim?

    /// The user's full name, in a displayable form.
    ///
    /// **Might** be provided when:
    /// - The request scope included the string "profile"
    /// - The ID token is returned from a token refresh
    ///
    /// When `name` claims are present, you can use them to update your app's user records.
    public let name: String?

    /// The URL of the user's profile picture.
    ///
    /// **Might** be provided when:
    /// - The request scope included the string "profile"
    /// - The ID token is returned from a token refresh
    ///
    /// When `picture` claims are present, you can use them to update your app's user records.
    public let picture: String?

    /// The URL of the user's profile picture.
    ///
    /// **Might** be provided when:
    /// - The request scope included the string "profile"
    /// - The ID token is returned from a token refresh
    ///
    /// When `profile` claims are present, you can use them to update your app's user records.
    public let profile: String?

    /// The user's given name(s) or first name(s). Might be provided when a `name` claim is present.
    public let givenName: String?

    /// The user's surname(s) or last name(s). Might be provided when a `name` claim is present.
    public let familyName: String?

    /// The user's locale, represented by a [BCP 47](https://tools.ietf.org/html/bcp47) language tag. Might be provided when a name claim is present.
    public let locale: LocaleClaim?

    /// The value of the nonce supplied by your app in the authentication request. You should enforce protection against replay attacks by ensuring it is presented only once.
    public let nonce: String?

    public init(
        issuer: IssuerClaim,
        subject: SubjectClaim,
        audience: AudienceClaim,
        authorizedPresenter: String,
        issuedAt: IssuedAtClaim,
        expires: ExpirationClaim,
        atHash: String? = nil,
        hostedDomain: GoogleHostedDomainClaim? = nil,
        email: String? = nil,
        emailVerified: BoolClaim? = nil,
        name: String? = nil,
        picture: String? = nil,
        profile: String? = nil,
        givenName: String? = nil,
        familyName: String? = nil,
        locale: LocaleClaim? = nil,
        nonce: String? = nil
    ) {
        self.issuer = issuer
        self.subject = subject
        self.audience = audience
        self.authorizedPresenter = authorizedPresenter
        self.issuedAt = issuedAt
        self.expires = expires
        self.atHash = atHash
        self.hostedDomain = hostedDomain
        self.email = email
        self.emailVerified = emailVerified
        self.name = name
        self.picture = picture
        self.profile = profile
        self.givenName = givenName
        self.familyName = familyName
        self.locale = locale
        self.nonce = nonce
    }

    public func verify(using _: some JWTAlgorithm) throws {
        guard ["accounts.google.com", "https://accounts.google.com"].contains(self.issuer.value) else {
            throw JWTError.claimVerificationFailure(failedClaim: issuer, reason: "Token not provided by Google")
        }

        guard self.subject.value.count <= 255 else {
            throw JWTError.claimVerificationFailure(failedClaim: subject, reason: "Subject claim beyond 255 ASCII characters long.")
        }

        try self.expires.verifyNotExpired()
    }
}
