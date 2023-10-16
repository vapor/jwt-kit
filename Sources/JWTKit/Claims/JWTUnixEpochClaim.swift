import Foundation

public protocol JWTUnixEpochClaim: JWTClaim where Value == Date { }

extension JWTUnixEpochClaim {
    /// See `Decodable`.
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        self.init(value: try container.decode(Date.self))
    }
    
    /// See `Encodable`.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.value)
    }
}
