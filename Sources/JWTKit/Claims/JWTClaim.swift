/// A claim is a codable, top-level property of a JWT payload. Multiple claims form a payload.
/// Some claims, such as expiration claims, are inherently verifiable. Each claim able to verify
/// itself provides an appropriate method for doing so, depending on the specific claim.
public protocol JWTClaim: Codable, Sendable {
    /// The associated value type.
    associatedtype Value: Codable

    /// The claim's value.
    var value: Value { get set }

    /// Initializes the claim with its value.
    init(value: Value)
}

extension JWTClaim where Value == String, Self: ExpressibleByStringLiteral {
    /// See `ExpressibleByStringLiteral`.
    public init(stringLiteral string: String) {
        self.init(value: string)
    }
}

extension JWTClaim {
    /// See `Decodable`.
    public init(from decoder: Decoder) throws {
        let single = try decoder.singleValueContainer()
        try self.init(value: single.decode(Value.self))
    }

    /// See `Encodable`.
    public func encode(to encoder: Encoder) throws {
        var single = encoder.singleValueContainer()
        try single.encode(value)
    }
}
