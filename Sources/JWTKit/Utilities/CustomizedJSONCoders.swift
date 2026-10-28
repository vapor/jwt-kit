#if !canImport(Darwin)
public import FoundationEssentials
#else
public import Foundation
#endif

public protocol JWTJSONDecoder: Sendable {
    func decode<T: Decodable>(_: T.Type, from string: Data) throws -> T
}

public protocol JWTJSONEncoder: Sendable {
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
    /// RFC 7519 Encoder that handles doubles outside the range of representable `Int` values by throwing
    /// an `EncodingError` rather than narrowing them to prevent an error when decoding the value back to a `Date`
    public static var integerSecondsSince1970: Self {
        .custom { date, encoder in
            let seconds = date.timeIntervalSince1970.rounded(.towardZero)
            guard let integerSeconds = Int(exactly: seconds) else {
                throw EncodingError.invalidValue(
                    date,
                    .init(
                        codingPath: encoder.codingPath,
                        debugDescription:
                            "Date is outside the range representable as an integer number of seconds since 1970."
                    ))
            }
            var container = encoder.singleValueContainer()
            try container.encode(integerSeconds)
        }
    }
}

extension JWTJSONEncoder where Self == JSONEncoder {
    public static var defaultForJWT: any JWTJSONEncoder {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        return encoder
    }
}

extension JWTJSONDecoder where Self == JSONDecoder {
    public static var defaultForJWT: any JWTJSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }
}
