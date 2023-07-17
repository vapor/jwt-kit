@_implementationOnly import CJWTKitBoringSSL
import Crypto
import Foundation

extension JWTSigner {
    // MARK: 256

    public static func hs256(key: String) -> JWTSigner { .hs256(key: key, jsonEncoder: nil, jsonDecoder: nil) }
    public static func hs256<Key: DataProtocol>(key: Key) -> JWTSigner { .hs256(key: key, jsonEncoder: nil, jsonDecoder: nil) }
    public static func hs256(key: SymmetricKey) -> JWTSigner { .hs256(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    public static func hs256(key: String, jsonEncoder: JSONEncoder?, jsonDecoder: JSONDecoder?) -> JWTSigner {
        .hs256(key: [UInt8](key.utf8), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    public static func hs256<Key>(key: Key, jsonEncoder: JSONEncoder?, jsonDecoder: JSONDecoder?) -> JWTSigner
        where Key: DataProtocol
    {
        let symmetricKey = SymmetricKey(data: key.copyBytes())
        return .hs256(key: symmetricKey, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }
    
    public static func hs256(key: SymmetricKey, jsonEncoder: JSONEncoder?, jsonDecoder: JSONDecoder?) -> JWTSigner {
        .init(algorithm: HMACSigner<SHA256>(key: key, name: "HS256"), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)

    }

    // MARK: 384

    public static func hs384(key: String) -> JWTSigner { .hs384(key: key, jsonEncoder: nil, jsonDecoder: nil) }
    public static func hs384<Key: DataProtocol>(key: Key) -> JWTSigner { .hs384(key: key, jsonEncoder: nil, jsonDecoder: nil) }
    public static func hs384(key: SymmetricKey) -> JWTSigner { .hs384(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    public static func hs384(key: String, jsonEncoder: JSONEncoder?, jsonDecoder: JSONDecoder?) -> JWTSigner {
        .hs384(key: [UInt8](key.utf8), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    public static func hs384<Key>(key: Key, jsonEncoder: JSONEncoder?, jsonDecoder: JSONDecoder?) -> JWTSigner
        where Key: DataProtocol
    {
        let symmetricKey = SymmetricKey(data: key.copyBytes())
        return .hs384(key: symmetricKey, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }
    
    public static func hs384(key: SymmetricKey, jsonEncoder: JSONEncoder?, jsonDecoder: JSONDecoder?) -> JWTSigner {
        .init(algorithm: HMACSigner<SHA384>(key: key, name: "HS384"), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    // MARK: 512

    public static func hs512(key: String) -> JWTSigner { .hs512(key: key, jsonEncoder: nil, jsonDecoder: nil) }
    public static func hs512<Key: DataProtocol>(key: Key) -> JWTSigner { .hs512(key: key, jsonEncoder: nil, jsonDecoder: nil) }
    public static func hs512(key: SymmetricKey) -> JWTSigner { .hs512(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    public static func hs512(key: String, jsonEncoder: JSONEncoder?, jsonDecoder: JSONDecoder?) -> JWTSigner {
        .hs512(key: [UInt8](key.utf8), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    public static func hs512<Key>(key: Key, jsonEncoder: JSONEncoder?, jsonDecoder: JSONDecoder?) -> JWTSigner
        where Key: DataProtocol
    {
        let symmetricKey = SymmetricKey(data: key.copyBytes())
        return .hs512(key: symmetricKey, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }
    
    public static func hs512(key: SymmetricKey, jsonEncoder: JSONEncoder?, jsonDecoder: JSONDecoder?) -> JWTSigner {
        .init(algorithm: HMACSigner<SHA512>(key: key, name: "HS512"), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }
}
