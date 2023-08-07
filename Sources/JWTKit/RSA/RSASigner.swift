import Foundation
import Crypto
import _CryptoExtras

internal struct RSASigner: JWTAlgorithm, CryptoSigner {
    let key: RSAKey
    var algorithm: DigestAlgorithm
    let name: String

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        guard case .private = self.key.type else {
            throw JWTError.signingAlgorithmFailure(RSAError.privateKeyRequired)
        }

        do {
            let privateKey = self.key.privateKey!
            let digest = try self.digest(plaintext)
            let signature = try privateKey.signature(for: digest)
            return [UInt8](signature.rawRepresentation)
        } catch {
            throw JWTError.signingAlgorithmFailure(RSAError.signFailure(error))
        }

    }

    func verify<Signature, Plaintext>(
        _ signature: Signature,
        signs plaintext: Plaintext
    ) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)
        let signature = _RSA.Signing.RSASignature(rawRepresentation: signature)

        let publicKey = self.key.privateKey?.publicKey ?? self.key.publicKey!
        return publicKey.isValidSignature(signature, for: digest)
    }
}
