@_implementationOnly import CJWTKitBoringSSL
import class Foundation.JSONEncoder
import class Foundation.JSONDecoder

extension JWTSigner {
    public static func es256(key: ECDSAKey) -> JWTSigner { .es256(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    public static func es256(key: ECDSAKey, jsonEncoder: JSONEncoder?, jsonDecoder: JSONDecoder?) -> JWTSigner {
        .init(algorithm: ECDSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha256(),
            name: "ES256"
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    public static func es384(key: ECDSAKey) -> JWTSigner { .es384(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    public static func es384(key: ECDSAKey, jsonEncoder: JSONEncoder?, jsonDecoder: JSONDecoder?) -> JWTSigner {
        .init(algorithm: ECDSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha384(),
            name: "ES384"
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    public static func es512(key: ECDSAKey) -> JWTSigner { .es512(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    public static func es512(key: ECDSAKey, jsonEncoder: JSONEncoder?, jsonDecoder: JSONDecoder?) -> JWTSigner {
        .init(algorithm: ECDSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha512(),
            name: "ES512"
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }
}
