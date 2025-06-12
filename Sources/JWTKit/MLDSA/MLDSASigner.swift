import _CryptoExtras

#if canImport(FoundationEssentials)
    import FoundationEssentials
#else
    import Foundation
#endif

struct MLDSASigner<Key: MLDSAKey>: JWTAlgorithm, Sendable {
    let privateKey: MLDSA.PrivateKey<Key.MLDSAType>?
    let publicKey: MLDSA.PublicKey<Key.MLDSAType>

    var name: String = Key.MLDSAType.name

    init(key: Key) {
        switch key {
        case let key as MLDSA.PrivateKey<Key.MLDSAType>:
            self.privateKey = key
            self.publicKey = key.publicKey
        case let key as MLDSA.PublicKey<Key.MLDSAType>:
            self.privateKey = nil
            self.publicKey = key
        default:
            fatalError()
        }
    }

    func sign(_ plaintext: some DataProtocol) throws -> [UInt8] {
        guard let privateKey else {
            throw JWTError.signingAlgorithmFailure(MLDSAError.noPrivateKey)
        }

        let signature: Data
        do {
            signature = try privateKey.backing.signature(for: plaintext)
        } catch {
            throw JWTError.signingAlgorithmFailure(MLDSAError.failedToSign(error))
        }

        return signature.copyBytes()
    }

    func verify(_ signature: some DataProtocol, signs plaintext: some DataProtocol) throws -> Bool {
        publicKey.backing.isValidSignature(signature, for: plaintext)
    }
}
