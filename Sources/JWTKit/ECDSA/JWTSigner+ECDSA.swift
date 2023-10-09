import class Foundation.JSONDecoder
import class Foundation.JSONEncoder

public extension JWTSigner {
    static func es256(key: P256Key) -> JWTSigner { .es256(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    static func es256(key: P256Key, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: ECDSASigner(
            key: key,
            algorithm: .sha256,
            name: "ES256"
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    // static func es384(key: ECDSAKey) -> JWTSigner { .es384(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    // static func es384(key: ECDSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
    //     .init(algorithm: ECDSASigner(
    //         key: key,
    //         algorithm: .sha384,
    //         name: "ES384"
    //     ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    // }

    // static func es512(key: ECDSAKey) -> JWTSigner { .es512(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    // static func es512(key: ECDSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
    //     .init(algorithm: ECDSASigner(
    //         key: key,
    //         algorithm: .sha512,
    //         name: "ES512"
    //     ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    // }
}
