import _CryptoExtras

public extension JWTSigner {
    static func rs256(key: RSAKey) -> JWTSigner { .rs256(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    static func rs256(key: RSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: .sha256,
            name: "RS256",
            padding: .insecurePKCS1v1_5
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    static func rs384(key: RSAKey) -> JWTSigner { .rs384(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    static func rs384(key: RSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: .sha384,
            name: "RS384",
            padding: .insecurePKCS1v1_5
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    static func rs512(key: RSAKey) -> JWTSigner { .rs512(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    static func rs512(key: RSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: .sha512,
            name: "RS512",
            padding: .insecurePKCS1v1_5
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    static func ps256(key: RSAKey) -> JWTSigner { .ps256(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    static func ps256(key: RSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: .sha256,
            name: "PS256",
            padding: .PSS
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    static func ps384(key: RSAKey) -> JWTSigner { .ps384(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    static func ps384(key: RSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: .sha384,
            name: "PS384",
            padding: .PSS
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    static func ps512(key: RSAKey) -> JWTSigner { .ps512(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    static func ps512(key: RSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: .sha512,
            name: "PS512",
            padding: .PSS
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }
}
