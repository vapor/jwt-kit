import Foundation

public protocol JWTJSONDecoder: Sendable {
    func decode<T: Decodable>(_: T.Type, from string: Data) throws -> T
}

public protocol JWTJSONEncoder: Sendable {
    func encode<T: Encodable>(_ value: T) throws -> Data
}

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

extension JWTJSONEncoder where Self == JSONEncoder {
    package static var defaultForJWT: any JWTJSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        return encoder
    }
}

extension JWTJSONDecoder where Self == JSONDecoder {
    package static var defaultForJWT: any JWTJSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }
}
