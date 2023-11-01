import Crypto
import Foundation

public extension JWTKeyCollection {
    func addEdDSA(
        key: EdDSAKey,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(algorithm: EdDSASigner(key: key), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder), for: kid)
    }
}
