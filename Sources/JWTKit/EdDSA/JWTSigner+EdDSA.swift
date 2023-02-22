import Foundation
import Crypto

extension JWTSigner {
    public static func eddsa(_ key: EdDSAKey) -> JWTSigner {
        .init(algorithm: EdDSASigner(key: key))
    }
}
