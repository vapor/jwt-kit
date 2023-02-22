import Foundation

public protocol JWTUnixEpochClaim: JWTClaim where Value == Date { }

extension JWTUnixEpochClaim {
    /// See `Decodable`.
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(value: .init(timeIntervalSince1970: container.decode(Double.self)))
    }
    
    /// See `Encodable`.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(value.timeIntervalSince1970)
    }
}
