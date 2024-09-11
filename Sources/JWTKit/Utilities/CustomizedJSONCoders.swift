#if canImport(Darwin)
import Foundation
#else
@preconcurrency import Foundation
#endif

#if canImport(Darwin)
public protocol JWTJSONDecoder: Sendable {
    func decode<T: Decodable>(_: T.Type, from string: Data) throws -> T
}

public protocol JWTJSONEncoder: Sendable {
    func encode<T: Encodable>(_ value: T) throws -> Data
}
#else
public protocol JWTJSONDecoder: @unchecked Sendable {
    func decode<T: Decodable>(_: T.Type, from string: Data) throws -> T
}

public protocol JWTJSONEncoder: @unchecked Sendable {
    func encode<T: Encodable>(_ value: T) throws -> Data
}
#endif

extension JSONDecoder: JWTJSONDecoder {}
extension JSONEncoder: JWTJSONEncoder {}

public extension JSONDecoder.DateDecodingStrategy {
    static var integerSecondsSince1970: Self {
        .custom { decoder in
            let container = try decoder.singleValueContainer()
            return try Date(timeIntervalSince1970: Double(container.decode(Int.self)))
        }
    }
}

public extension JSONEncoder.DateEncodingStrategy {
    static var integerSecondsSince1970: Self {
        .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(Int(date.timeIntervalSince1970.rounded(.towardZero)))
        }
    }
}

public extension JWTJSONEncoder where Self == JSONEncoder {
    static var defaultForJWT: any JWTJSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        return encoder
    }
}

public extension JWTJSONDecoder where Self == JSONDecoder {
    static var defaultForJWT: any JWTJSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }
}
