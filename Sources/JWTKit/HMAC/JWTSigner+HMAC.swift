import Crypto
import Foundation

public extension JWTSigner {
    // MARK: 256

    static func hs256(key: String) -> JWTSigner { .hs256(key: key, jsonEncoder: nil, jsonDecoder: nil) }
    static func hs256<Key: DataProtocol>(key: Key) -> JWTSigner { .hs256(key: key, jsonEncoder: nil, jsonDecoder: nil) }
    static func hs256(key: SymmetricKey) -> JWTSigner { .hs256(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    static func hs256(key: String, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .hs256(key: [UInt8](key.utf8), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    static func hs256(key: some DataProtocol, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        let symmetricKey = SymmetricKey(data: key.copyBytes())
        return .hs256(key: symmetricKey, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    static func hs256(key: SymmetricKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: HMACSigner<SHA256>(key: key, name: "HS256"), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    // MARK: 384

    static func hs384(key: String) -> JWTSigner { .hs384(key: key, jsonEncoder: nil, jsonDecoder: nil) }
    static func hs384(key: some DataProtocol) -> JWTSigner { .hs384(key: key, jsonEncoder: nil, jsonDecoder: nil) }
    static func hs384(key: SymmetricKey) -> JWTSigner { .hs384(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    static func hs384(key: String, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .hs384(key: [UInt8](key.utf8), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    static func hs384(key: some DataProtocol, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        let symmetricKey = SymmetricKey(data: key.copyBytes())
        return .hs384(key: symmetricKey, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    static func hs384(key: SymmetricKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: HMACSigner<SHA384>(key: key, name: "HS384"), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    // MARK: 512

    static func hs512(key: String) -> JWTSigner { .hs512(key: key, jsonEncoder: nil, jsonDecoder: nil) }
    static func hs512(key: some DataProtocol) -> JWTSigner { .hs512(key: key, jsonEncoder: nil, jsonDecoder: nil) }
    static func hs512(key: SymmetricKey) -> JWTSigner { .hs512(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    static func hs512(key: String, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .hs512(key: [UInt8](key.utf8), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    static func hs512(key: some DataProtocol, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        let symmetricKey = SymmetricKey(data: key.copyBytes())
        return .hs512(key: symmetricKey, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    static func hs512(key: SymmetricKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: HMACSigner<SHA512>(key: key, name: "HS512"), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }
}
