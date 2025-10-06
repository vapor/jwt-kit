#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

public struct LocaleClaim: JWTClaim, Equatable, ExpressibleByStringLiteral {
    /// See ``JWTClaim``.
    public var value: Locale

    /// See ``JWTClaim``.
    public init(value: Locale) {
        self.value = value
    }

    public init(stringLiteral value: String) {
        self.value = Locale(identifier: value)
    }

    /// See `Decodable`.
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(value: Locale(identifier: container.decode(String.self)))
    }

    /// See `Encodable`.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(value.identifier)
    }
}
