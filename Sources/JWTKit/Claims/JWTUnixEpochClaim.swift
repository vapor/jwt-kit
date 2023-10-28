import Foundation

public protocol JWTUnixEpochClaim: JWTClaim where Value == Date {}

public extension JWTUnixEpochClaim {
    /// See `Decodable`.
    init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(value: container.decode(Date.self))
    }

    /// See `Encodable`.
    func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.value)
    }
}
