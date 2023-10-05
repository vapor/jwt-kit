public extension JWTSigner {
    static func rs256(key: RSAKey) -> JWTSigner { .rs256(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    static func rs256(key: RSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: .sha256,
            name: "RS256"
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    static func rs384(key: RSAKey) -> JWTSigner { .rs384(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    static func rs384(key: RSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: .sha384,
            name: "RS384"
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    static func rs512(key: RSAKey) -> JWTSigner { .rs512(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    static func rs512(key: RSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: RSASigner(
            key: key,
            algorithm: .sha512,
            name: "RS512"
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }
}
