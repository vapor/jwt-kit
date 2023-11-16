public struct GoogleHostedDomainClaim: JWTClaim, Equatable, ExpressibleByStringLiteral {
    /// See ``JWTClaim``.
    public var value: String

    /// See ``JWTClaim``.
    public init(value: String) {
        self.value = value
    }

    public func verify(domain: String) throws {
        guard value == domain else {
            throw JWTError.claimVerificationFailure(failedClaim: self, reason: "\(value) is invalid")
        }
    }
}
