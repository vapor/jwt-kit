import Foundation
import Crypto

internal struct HMACSigner<SHAType>: JWTAlgorithm where SHAType: HashFunction {
    let key: SymmetricKey
    let name: String

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        let authentication = Crypto.HMAC<SHAType>.authenticationCode(for: plaintext, using: self.key)
        return Array(authentication)
    }
}
