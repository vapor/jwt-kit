import Foundation

public protocol JWTJSONDecoder {
    func decode<T: Decodable>(_: T.Type, from string: Data) throws -> T
}

public protocol JWTJSONEncoder {
    func encode<T: Encodable>(_ value: T) throws -> Data
}

extension JSONDecoder: JWTJSONDecoder {}

extension JSONEncoder: JWTJSONEncoder {}

extension JSONDecoder.DateDecodingStrategy {
    public static var integerSecondsSince1970: Self {
        .custom { decoder in
            let container = try decoder.singleValueContainer()
            return try Date(timeIntervalSince1970: Double(container.decode(Int.self)))
        }
    }
}

extension JSONEncoder.DateEncodingStrategy {
    public static var integerSecondsSince1970: Self {
        .custom { date, encoder in
            var container = encoder.singleValueContainer()
            try container.encode(Int(date.timeIntervalSince1970.rounded(.towardZero)))
        }
    }
}

extension JWTJSONEncoder where Self == JSONEncoder {
    static var defaultForJWT: any JWTJSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        return encoder
    }
}

extension JWTJSONDecoder where Self == JSONDecoder {
    static var defaultForJWT: any JWTJSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }
}
