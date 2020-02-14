/// A claim which represents a bool
///
/// If a string is provided, and the string doesn't represent a bool, then `false` will be used.
public struct BoolClaim: JWTClaim, Equatable, ExpressibleByStringLiteral, ExpressibleByBooleanLiteral {
    /// See `JWTClaim
    public var value: Bool

    /// See `JWTClaim`.
    public init(value: Bool) {
        self.value = value
    }

    public init(stringLiteral value: String) {
        self.value = Bool(value) ?? false
    }

    public init(booleanLiteral value: Bool) {
        self.value = value
    }
}
