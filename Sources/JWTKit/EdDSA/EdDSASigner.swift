import Crypto
import Foundation

struct EdDSASigner: JWTAlgorithm, Sendable {
    let key: EdDSAKey
    let name = "EdDSA"

    func sign(_ plaintext: some DataProtocol) throws -> [UInt8] {
        guard let privateKey = key.privateKey else {
            throw JWTError.signingAlgorithmFailure(EdDSAError.privateKeyMissing)
        }

        switch key.curve {
        case .ed25519:
            return try Curve25519.Signing.PrivateKey(
                rawRepresentation: privateKey
            ).signature(
                for: plaintext
            ).copyBytes()
        }
    }

    func verify(_ signature: some DataProtocol, signs plaintext: some DataProtocol) throws -> Bool {
        switch key.curve {
        case .ed25519:
            return try Curve25519.Signing.PublicKey(
                rawRepresentation: key.publicKey
            ).isValidSignature(
                signature,
                for: plaintext
            )
        }
    }
}
