@_implementationOnly import CJWTKitBoringSSL

extension JWTSigner {
    public static func rs256(key: RSAKey) -> JWTSigner { .rs256(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    public static func rs256(key: RSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: .sha256
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    public static func rs384(key: RSAKey) -> JWTSigner { .rs384(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    public static func rs384(key: RSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: .sha384
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    public static func rs512(key: RSAKey) -> JWTSigner { .rs512(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    public static func rs512(key: RSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: .sha512
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }
}
