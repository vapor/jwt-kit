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
        case orgId = "org_id"
        case realUserStatus = "real_user_status"
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

    /// Managed Apple ID organization (see https://developer.apple.com/documentation/rosterapi/integrating_with_roster_api_and_sign_in_with_apple)
    public let orgId: String?

    /// A Boolean value that indicates whether the service has verified the email. The value of this claim is always true because the servers only return verified email addresses.
    public let emailVerified: BoolClaim?

    /// A Boolean value that indicates whether the email shared by the user is the proxy address. It is absent (nil) if the user is not using a proxy email address.
    public let isPrivateEmail: BoolClaim?

    /// A value that indicates whether the user appears to be a real person.
    public let realUserStatus: UserDetectionStatus?

    public init(
        issuer: IssuerClaim,
        audience: AudienceClaim,
        expires: ExpirationClaim,
        issuedAt: IssuedAtClaim,
        subject: SubjectClaim,
        nonceSupported: BoolClaim? = nil,
        nonce: String? = nil,
        email: String? = nil,
        orgId: String? = nil,
        emailVerified: BoolClaim? = nil,
        isPrivateEmail: BoolClaim? = nil,
        realUserStatus: UserDetectionStatus? = nil
    ) {
        self.issuer = issuer
        self.audience = audience
        self.expires = expires
        self.issuedAt = issuedAt
        self.subject = subject
        self.nonceSupported = nonceSupported
        self.nonce = nonce
        self.email = email
        self.orgId = orgId
        self.emailVerified = emailVerified
        self.isPrivateEmail = isPrivateEmail
        self.realUserStatus = realUserStatus
    }

    public func verify(using _: some JWTAlgorithm) throws {
        guard self.issuer.value == "https://appleid.apple.com" else {
            throw JWTError.claimVerificationFailure(failedClaim: issuer, reason: "Token not provided by Apple")
        }

        try self.expires.verifyNotExpired()
    }
}

extension AppleIdentityToken {
    /// Taken from https://developer.apple.com/documentation/authenticationservices/asuserdetectionstatus
    /// With slight modification to make adding new cases non-breaking.
    public struct UserDetectionStatus: OptionSet, Codable, Sendable {
        /// Used for decoding/encoding
        private enum Status: Int, Codable {
            case unsupported
            case unknown
            case likelyReal
        }

        /// Not supported on current platform, ignore the value
        public static let unsupported = UserDetectionStatus([])  // 0 was giving a warning

        /// We could not determine the value.  New users in the ecosystem will get this value as well, so you should not block these users, but instead treat them as any new user through standard email sign up flows
        public static let unknown = UserDetectionStatus(rawValue: 1)

        /// A hint that we have high confidence that the user is real
        public static let likelyReal = UserDetectionStatus(rawValue: 2)

        public let rawValue: Int

        public init(rawValue: Int) {
            self.rawValue = rawValue
        }

        public init(from decoder: Decoder) throws {
            let value = try decoder.singleValueContainer().decode(Status.self)
            switch value {
            case .unsupported: self = .unsupported
            case .unknown: self = .unknown
            case .likelyReal: self = .likelyReal
            }
        }

        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            switch self {
            case .unsupported: try container.encode(Status.unsupported)
            case .unknown: try container.encode(Status.unknown)
            case .likelyReal: try container.encode(Status.likelyReal)
            default:
                let context = EncodingError.Context(codingPath: encoder.codingPath, debugDescription: "Invalid enum value: \(self)")
                throw EncodingError.invalidValue(self, context)
            }
        }
    }
}
