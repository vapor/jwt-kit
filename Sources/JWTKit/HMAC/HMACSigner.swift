import Crypto

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

struct HMACSigner<SHAType>: JWTAlgorithm where SHAType: HashFunction {
    let key: SymmetricKey
    let name: String

    init(key: SymmetricKey) {
        assert(
            key.bitCount >= SHAType.Digest.byteCount * 8,
            "Key should be at least as large as the hash output: \(SHAType.Digest.byteCount) bytes. This will become a precondition in a future release."
        )
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

    /// Compare using Swift Crypto
    func verify(_ signature: some DataProtocol, signs plaintext: some DataProtocol) throws -> Bool {
        HMAC<SHAType>.isValidAuthenticationCode(
            Array(signature), authenticating: plaintext, using: self.key)
    }
}
