import _CryptoExtras

public extension JWTSigner {
    static func rs256(key: RSAKey, padding: _RSA.Signing.Padding = .PSS) -> JWTSigner { .rs256(key: key, padding: padding, jsonEncoder: nil, jsonDecoder: nil) }

    static func rs256(key: RSAKey, padding: _RSA.Signing.Padding = .PSS, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: .sha256,
            name: "RS256",
            padding: padding
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    static func rs384(key: RSAKey, padding: _RSA.Signing.Padding = .PSS) -> JWTSigner { .rs384(key: key, padding: padding, jsonEncoder: nil, jsonDecoder: nil) }

    static func rs384(key: RSAKey, padding: _RSA.Signing.Padding = .PSS, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: .sha384,
            name: "RS384",
            padding: padding
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    static func rs512(key: RSAKey, padding: _RSA.Signing.Padding = .PSS) -> JWTSigner { .rs512(key: key, padding: padding, jsonEncoder: nil, jsonDecoder: nil) }

    static func rs512(key: RSAKey, padding: _RSA.Signing.Padding = .PSS, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: .sha512,
            name: "RS512",
            padding: padding
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }
}
