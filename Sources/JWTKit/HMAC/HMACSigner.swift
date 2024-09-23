@preconcurrency import Crypto
import Foundation

struct HMACSigner<SHAType>: JWTAlgorithm where SHAType: HashFunction {
    let key: SymmetricKey
    let name: String

    func sign(_ plaintext: some DataProtocol) throws -> [UInt8] {
        let authentication = Crypto.HMAC<SHAType>.authenticationCode(
            for: plaintext, using: self.key)
        return Array(authentication)
    }
}
