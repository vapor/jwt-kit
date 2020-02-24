import Crypto
import Foundation

internal struct HMACSigner<SHA_TYPE>: JWTAlgorithm where SHA_TYPE: HashFunction {
    let key: SymmetricKey
    let name: String

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        let authentication = Crypto.HMAC<SHA_TYPE>.authenticationCode(for: plaintext, using: self.key)
        return Array(authentication)
    }
}
