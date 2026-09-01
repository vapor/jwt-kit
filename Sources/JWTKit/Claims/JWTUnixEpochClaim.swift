#if !canImport(Darwin)
public import FoundationEssentials
#else
public import Foundation
#endif

public protocol JWTUnixEpochClaim: JWTClaim where Value == Date {}

extension JWTUnixEpochClaim {
    /// See `Decodable`.
    public init(from decoder: any Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(value: container.decode(Date.self))
    }

    /// See `Encodable`.
    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.value)
    }
}
