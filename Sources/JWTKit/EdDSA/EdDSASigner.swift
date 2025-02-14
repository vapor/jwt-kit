import Crypto

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

struct EdDSASigner: JWTAlgorithm, Sendable {
    let publicKey: EdDSA.PublicKey
    let privateKey: EdDSA.PrivateKey?
    let name = "EdDSA"

    init(key: some EdDSAKey) {
        switch key {
        case let key as EdDSA.PrivateKey:
            self.privateKey = key
            self.publicKey = key.publicKey
        case let key as EdDSA.PublicKey:
            self.publicKey = key
            self.privateKey = nil
        default:
            // This should never happen
            fatalError("Unexpected key type: \(type(of: key))")
        }
    }

    func sign(_ plaintext: some DataProtocol) throws -> [UInt8] {
        guard let privateKey else {
            throw JWTError.signingAlgorithmFailure(EdDSAError.privateKeyMissing)
        }

        switch privateKey.curve.backing {
        case .ed25519:
            return try Curve25519.Signing.PrivateKey(rawRepresentation: privateKey.rawRepresentation)
                .signature(for: plaintext).copyBytes()
        }
    }

    func verify(_ signature: some DataProtocol, signs plaintext: some DataProtocol) throws -> Bool {
        switch publicKey.curve.backing {
        case .ed25519:
            try Curve25519.Signing.PublicKey(rawRepresentation: publicKey.rawRepresentation)
                .isValidSignature(signature, for: plaintext)
        }
    }
}
