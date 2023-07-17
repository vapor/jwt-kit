@_implementationOnly import CJWTKitBoringSSL
import class Foundation.JSONEncoder
import class Foundation.JSONDecoder

extension JWTSigner {
    public static func rs256(key: RSAKey) -> JWTSigner { .rs256(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    public static func rs256(key: RSAKey, jsonEncoder: JSONEncoder?, jsonDecoder: JSONDecoder?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha256(),
            name: "RS256"
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    public static func rs384(key: RSAKey) -> JWTSigner { .rs384(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    public static func rs384(key: RSAKey, jsonEncoder: JSONEncoder?, jsonDecoder: JSONDecoder?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha384(),
            name: "RS384"
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    public static func rs512(key: RSAKey) -> JWTSigner { .rs512(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    public static func rs512(key: RSAKey, jsonEncoder: JSONEncoder?, jsonDecoder: JSONDecoder?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha512(),
            name: "RS512"
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }
}
