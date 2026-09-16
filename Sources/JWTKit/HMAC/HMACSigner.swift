import Crypto

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

struct HMACSigner<SHAType>: JWTAlgorithm where SHAType: HashFunction {
    private let keyedMAC: HMAC<SHAType>
    let name: String

    init(key: SymmetricKey) {
        assert(
            key.bitCount >= SHAType.Digest.byteCount * 8,
            "Key should be at least as large as the hash output: \(SHAType.Digest.byteCount) bytes. This will become a precondition in a future release."
        )
        self.keyedMAC = HMAC<SHAType>(key: key)
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
        var mac = self.keyedMAC
        mac.update(data: plaintext)
        return unsafe mac.finalize().withUnsafeBytes { unsafe [UInt8]($0) }
    }
}
