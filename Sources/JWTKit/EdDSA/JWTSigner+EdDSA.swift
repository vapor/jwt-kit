import Crypto
import Foundation

public extension JWTSigner {
    static func eddsa(_ key: EdDSAKey) -> JWTSigner { .eddsa(key, jsonEncoder: nil, jsonDecoder: nil) }

    static func eddsa(_ key: EdDSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: EdDSASigner(key: key), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }
}
