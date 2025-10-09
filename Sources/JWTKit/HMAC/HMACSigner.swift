@preconcurrency import Crypto

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

struct HMACSigner<SHAType>: JWTAlgorithm where SHAType: HashFunction {
    let key: SymmetricKey
    let name: String

    init(key: SymmetricKey) {
        self.key = key
        switch SHAType.self {
        case is SHA256.Type:
            self.name = "HS256"
        case is SHA384.Type:
            self.name = "HS384"
        case is SHA512.Type:
            self.name = "HS512"
        default:
            fatalError("Unsupported hash function: \(SHAType.self)")
        }
    }

    func sign(_ plaintext: some DataProtocol) throws -> [UInt8] {
        Array(HMAC<SHAType>.authenticationCode(for: plaintext, using: self.key))
    }
}
