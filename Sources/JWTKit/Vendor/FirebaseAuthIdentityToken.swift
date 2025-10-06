#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

public struct FirebaseAuthIdentityToken: JWTPayload {
    /// Additional Firebase-specific claims
    public struct Firebase: Codable, Sendable {
        enum CodingKeys: String, CodingKey {
            case identities
            case signInProvider = "sign_in_provider"
            case signInSecondFactor = "sign_in_second_factor"
            case secondFactorIdentifier = "second_factor_identifier"
            case tenant
        }

        public init(
            identities: [String: [String]],
            signInProvider: String,
            signInSecondFactor: String? = nil,
            secondFactorIdentifier: String? = nil,
            tenant: String? = nil
        ) {
            self.identities = identities
            self.signInProvider = signInProvider
            self.signInSecondFactor = signInSecondFactor
            self.secondFactorIdentifier = secondFactorIdentifier
            self.tenant = tenant
        }

        public let identities: [String: [String]]
        public let signInProvider: String
        public let signInSecondFactor: String?
        public let secondFactorIdentifier: String?
        public let tenant: String?
    }

    enum CodingKeys: String, CodingKey {
        case email, name, picture, firebase
        case issuer = "iss"
        case subject = "sub"
        case audience = "aud"
        case issuedAt = "iat"
        case expires = "exp"
        case emailVerified = "email_verified"
        case userID = "user_id"
        case authTime = "auth_time"
        case phoneNumber = "phone_number"
    }

    /// Issuer. It must be "https://securetoken.google.com/<projectId>", where <projectId> is the same project ID used for aud
    public let issuer: IssuerClaim

    /// Issued-at time. It must be in the past. The time is measured in seconds since the UNIX epoch.
    public let issuedAt: IssuedAtClaim

    /// Expiration time. It must be in the future. The time is measured in seconds since the UNIX epoch.
    public let expires: ExpirationClaim

    /// The audience that this ID token is intended for. It must be your Firebase project ID, the unique identifier for your Firebase project, which can be found in the URL of that project's console.
    public let audience: AudienceClaim

    /// Subject. It must be a non-empty string and must be the uid of the user or device.
    public let subject: SubjectClaim

    /// Authentication time. It must be in the past. The time when the user authenticated.
    public let authTime: Date?

    public let userID: String

    /// The user's email address.
    public let email: String?

    /// The URL of the user's profile picture.
    public let picture: String?

    /// The user's full name, in a displayable form.
    public let name: String?

    /// `True` if the user's e-mail address has been verified; otherwise `false`.
    public let emailVerified: Bool?

    /// The user's phone number.
    public let phoneNumber: String?

    /// Additional Firebase-specific claims
    public let firebase: Firebase?

    // TODO: support custom claims

    public init(
        issuer: IssuerClaim,
        subject: SubjectClaim,
        audience: AudienceClaim,
        issuedAt: IssuedAtClaim,
        expires: ExpirationClaim,
        authTime: Date? = nil,
        userID: String,
        email: String? = nil,
        emailVerified: Bool? = nil,
        phoneNumber: String? = nil,
        name: String? = nil,
        picture: String? = nil,
        firebase: FirebaseAuthIdentityToken.Firebase? = nil
    ) {
        self.issuer = issuer
        self.issuedAt = issuedAt
        self.expires = expires
        self.audience = audience
        self.subject = subject
        self.authTime = authTime
        self.userID = userID
        self.email = email
        self.picture = picture
        self.name = name
        self.emailVerified = emailVerified
        self.phoneNumber = phoneNumber
        self.firebase = firebase
    }

    public func verify(using _: some JWTAlgorithm) throws {
        guard let projectId = self.audience.value.first else {
            throw JWTError.claimVerificationFailure(failedClaim: audience, reason: "Token not provided by Firebase")
        }

        guard self.issuer.value == "https://securetoken.google.com/\(projectId)" else {
            throw JWTError.claimVerificationFailure(failedClaim: issuer, reason: "Token not provided by Firebase")
        }

        guard self.subject.value.count <= 255 else {
            throw JWTError.claimVerificationFailure(failedClaim: subject, reason: "Subject claim beyond 255 ASCII characters long.")
        }

        try self.expires.verifyNotExpired()
    }
}
