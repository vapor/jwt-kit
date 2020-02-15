import struct Foundation.Locale

public struct LocaleClaim: JWTClaim, Equatable, ExpressibleByStringLiteral {
    /// See `JWTClaim
    public var value: Locale

    /// See `JWTClaim`.
    public init(value: Locale) {
        self.value = value
    }

    public init(stringLiteral value: String) {
        self.value = Locale(identifier: value)
    }
}
