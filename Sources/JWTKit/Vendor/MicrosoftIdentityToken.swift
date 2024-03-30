/// - See Also:
/// [Retrieve the User’s Information from Microsoft Servers](https://docs.microsoft.com/pl-pl/azure/active-directory/develop/id-tokens)
public struct MicrosoftIdentityToken: JWTPayload {
    enum CodingKeys: String, CodingKey {
        case nonce, email, name, roles
        case audience = "aud"
        case issuer = "iss"
        case issuedAt = "iat"
        case identityProvider = "idp"
        case notBefore = "nbf"
        case expires = "exp"
        case codeHash = "c_hash"
        case accessTokenHash = "at_hash"
        case preferredUsername = "preferred_username"
        case objectId = "oid"
        case subject = "sub"
        case tenantId = "tid"
        case uniqueName = "unique_name"
        case version = "ver"
    }

    /// Identifies the intended recipient of the token. In id_tokens, the audience is your app's Application ID, assigned to your app
    /// in the Azure portal. Your app should validate this value, and reject the token if the value does not match.
    public let audience: AudienceClaim

    /// Identifies the security token service (STS) that constructs and returns the token, and the Azure AD tenant in which the user
    /// was authenticated. If the token was issued by the v2.0 endpoint, the URI will end in /v2.0. The GUID that indicates that the
    /// user is a consumer user from a Microsoft account is 9188040d-6c67-4c5b-b112-36a304b66dad. Your app should use the
    /// GUID portion of the claim to restrict the set of tenants that can sign in to the app, if applicable.
    public let issuer: IssuerClaim

    /// "Issued At" indicates when the authentication for this token occurred.
    public let issuedAt: IssuedAtClaim

    /// Records the identity provider that authenticated the subject of the token. This value is identical to the value of the Issuer claim
    /// unless the user account not in the same tenant as the issuer - guests, for instance. If the claim isn't present, it means that the
    /// value of iss can be used instead. For personal accounts being used in an organizational context (for instance, a personal account
    /// invited to an Azure AD tenant), the idp claim may be 'live.com' or an STS URI containing the Microsoft account
    /// tenant 9188040d-6c67-4c5b-b112-36a304b66dad.
    public let identityProvider: String?

    /// The "nbf" (not before) claim identifies the time before which the JWT MUST NOT be accepted for processing.
    public let notBefore: NotBeforeClaim

    /// The "exp" (expiration time) claim identifies the expiration time on or after which the JWT MUST NOT be accepted for
    /// processing. It's important to note that a resource may reject the token before this time as well - if, for example,
    /// a change in authentication is required or a token revocation has been detected.
    public let expires: ExpirationClaim

    /// The code hash is included in ID tokens only when the ID token is issued with an OAuth 2.0 authorization code.
    /// It can be used to validate the authenticity of an authorization code. For details about performing this validation,
    /// see the [OpenID Connect specification](https://openid.net/specs/openid-connect-core-1_0.html).
    public let codeHash: String?

    /// The access token hash is included in ID tokens only when the ID token is issued with an OAuth 2.0 access token.
    /// It can be used to validate the authenticity of an access token. For details about performing this validation,
    /// see the [OpenID Connect specification](https://openid.net/specs/openid-connect-core-1_0.html).
    public let accessTokenHash: String?

    /// The primary username that represents the user. It could be an email address, phone number, or a generic username
    /// without a specified format. Its value is mutable and might change over time. Since it is mutable, this value must not be
    /// used to make authorization decisions. The profile scope is required to receive this claim.
    public let preferredUsername: String?

    /// The email claim is present by default for guest accounts that have an email address. Your app can request the email
    /// claim for managed users (those from the same tenant as the resource) using the email optional claim. On the v2.0 endpoint,
    /// your app can also request the email OpenID Connect scope - you don't need to request both the optional claim and the scope
    /// to get the claim. The email claim only supports addressable mail from the user's profile information.
    public let email: String?

    /// The name claim provides a human-readable value that identifies the subject of the token. The value isn't guaranteed
    /// to be unique, it is mutable, and it's designed to be used only for display purposes. The profile scope is required to receive this claim.
    public let name: String?

    /// The nonce matches the parameter included in the original /authorize request to the IDP. If it does not match,
    /// your application should reject the token.
    public let nonce: String?

    /// The immutable identifier for an object in the Microsoft identity system, in this case, a user account. This ID uniquely identifies
    /// the user across applications - two different applications signing in the same user will receive the same value in the oid claim.
    /// The Microsoft Graph will return this ID as the id property for a given user account. Because the oid allows multiple apps to
    /// correlate users, the profile scope is required to receive this claim. Note that if a single user exists in multiple tenants, the user
    /// will contain a different object ID in each tenant - they're considered different accounts, even though the user logs into each
    /// account with the same credentials. The oid claim is a GUID and cannot be reused.
    public let objectId: String

    /// The set of roles that were assigned to the user who is logging in.
    public let roles: [String]?

    /// The principal about which the token asserts information, such as the user of an app. This value is immutable and cannot
    /// be reassigned or reused. The subject is a pairwise identifier - it is unique to a particular application ID. If a single user signs
    /// into two different apps using two different client IDs, those apps will receive two different values for the subject claim.
    /// This may or may not be wanted depending on your architecture and privacy requirements.
    public let subject: SubjectClaim

    /// A GUID that represents the Azure AD tenant that the user is from. For work and school accounts, the GUID is the
    /// immutable tenant ID of the organization that the user belongs to. For personal accounts, the value is
    /// 9188040d-6c67-4c5b-b112-36a304b66dad. The profile scope is required to receive this claim.
    public let tenantId: TenantIDClaim

    /// Provides a human readable value that identifies the subject of the token. This value is unique at any given point in time
    ///  but as emails and other identifiers can be reused, this value can reappear on other accounts, and should therefore be
    ///  used only for display purposes. Only issued in v1.0 id_tokens.
    public let uniqueName: String?

    /// Indicates the version of the id_token.
    public let version: String?

    public init(
        audience: AudienceClaim,
        issuer: IssuerClaim,
        issuedAt: IssuedAtClaim,
        identityProvider: String?,
        notBefore: NotBeforeClaim,
        expires: ExpirationClaim,
        codeHash: String?,
        accessTokenHash: String?,
        preferredUsername: String?,
        email: String?,
        name: String?,
        nonce: String?,
        objectId: String,
        roles: [String]?,
        subject: SubjectClaim,
        tenantId: TenantIDClaim,
        uniqueName: String?,
        version: String?
    ) {
        self.audience = audience
        self.issuer = issuer
        self.issuedAt = issuedAt
        self.identityProvider = identityProvider
        self.notBefore = notBefore
        self.expires = expires
        self.codeHash = codeHash
        self.accessTokenHash = accessTokenHash
        self.preferredUsername = preferredUsername
        self.email = email
        self.name = name
        self.nonce = nonce
        self.objectId = objectId
        self.roles = roles
        self.subject = subject
        self.tenantId = tenantId
        self.uniqueName = uniqueName
        self.version = version
    }

    public func verify(using _: some JWTAlgorithm) throws {
        guard let tenantId = self.tenantId.value else {
            throw JWTError.claimVerificationFailure(failedClaim: tenantId, reason: "Token must contain tenant Id")
        }

        guard self.issuer.value == "https://login.microsoftonline.com/\(tenantId)/v2.0" else {
            throw JWTError.claimVerificationFailure(failedClaim: issuer, reason: "Token not provided by Microsoft")
        }

        try self.expires.verifyNotExpired()
    }
}
