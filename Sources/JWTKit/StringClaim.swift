public protocol StringClaimTag {
    static var name: String { get }
}

public struct AudienceTag: StringClaimTag {
    public static var name: String { "aud" }
}

public struct IssuerTag: StringClaimTag {
    public static var name: String { "iss" }
}

public struct SubjectTag: StringClaimTag {
    public static var name: String { "sub" }
}

public struct IdTag: StringClaimTag {
    public static var name: String { "jti" }
}

public struct StringClaim<T: StringClaimTag>: JWTClaim, Equatable, ExpressibleByStringLiteral {
    public var value: String

    public init(value: String) {
        self.value = value
    }

    func verify(is desired: String) throws {
        guard desired == self.value else {
            throw JWTError.claimVerificationFailure(name: T.name, reason: "Value is incorrect.")
        }
    }

    func verify(oneOf desired: String...) throws {
        guard desired.contains(self.value) else {
            throw JWTError.claimVerificationFailure(name: T.name, reason: "Not one of the allowed values.")
        }
    }

    func verify(oneOf desired: [String]) throws {
        guard desired.contains(self.value) else {
            throw JWTError.claimVerificationFailure(name: T.name, reason: "Not one of the allowed values.")
        }
    }
}
