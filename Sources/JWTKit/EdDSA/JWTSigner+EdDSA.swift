import Foundation
import Crypto

extension JWTSigner {
    public static func eddsa(_ key: EdDSAKey) -> JWTSigner { .eddsa(key, jsonEncoder: nil, jsonDecoder: nil) }

    public static func eddsa(_ key: EdDSAKey, jsonEncoder: JSONEncoder?, jsonDecoder: JSONDecoder?) -> JWTSigner {
        .init(algorithm: EdDSASigner(key: key), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }
}
