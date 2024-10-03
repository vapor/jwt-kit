/// A claim which represents a bool
///
/// If a string is provided, and the string doesn't represent a bool, then `false` will be used.
public struct BoolClaim: JWTClaim, Equatable, ExpressibleByStringLiteral, ExpressibleByBooleanLiteral {
    /// See ``JWTClaim``.
    public var value: Bool

    /// See ``JWTClaim``.
    public init(value: Bool) {
        self.value = value
    }

    public init(stringLiteral value: String) {
        self.value = Bool(value) ?? false
    }

    public init(booleanLiteral value: Bool) {
        self.value = value
    }

    public init(from decoder: Decoder) throws {
        let single = try decoder.singleValueContainer()

        do {
            try self.init(value: single.decode(Bool.self))
        } catch {
            let str = try single.decode(String.self)
            guard let bool = Bool(str) else {
                throw JWTError.invalidBool(str)
            }

            self.init(value: bool)
        }
    }
}
