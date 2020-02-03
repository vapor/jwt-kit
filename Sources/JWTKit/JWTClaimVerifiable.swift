public protocol JWTClaimVerifiable: JWTClaim, Equatable, ExpressibleByStringLiteral where Value: Equatable {
    static var claimName: String { get }

    func verify(oneOf desired: Value...) throws
    func verify(oneOf desired: [Value]) throws
    func verify(is desired: Value) throws
}

public extension JWTClaimVerifiable {
    func verify(is desired: Value) throws {
        guard desired == self.value else {
            throw JWTError.claimVerificationFailure(name: Self.claimName, reason: "Issuer is incorrect.")
        }
    }

    func verify(oneOf desired: Value...) throws {
        guard desired.contains(self.value) else {
            throw JWTError.claimVerificationFailure(name: Self.claimName, reason: "Not one of the allowed values.")
        }
    }

    func verify(oneOf desired: [Value]) throws {
        guard desired.contains(self.value) else {
            throw JWTError.claimVerificationFailure(name: Self.claimName, reason: "Not one of the allowed values.")
        }
    }
}
