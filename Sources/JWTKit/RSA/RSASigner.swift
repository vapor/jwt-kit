import Foundation
import Crypto
import _CryptoExtras

internal struct RSASigner: JWTAlgorithm, CryptoSigner {
    var algorithm: DigestAlgorithm
    let key: RSAKey
    let name: String

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        guard case .private = self.key.type else {
            throw JWTError.signingAlgorithmFailure(RSAError.privateKeyRequired)
        }

        do {
            let privateKey = try _RSA.Signing.PrivateKey(pemRepresentation: "")
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
        let signature = _RSA.Signing.RSASignature.init(rawRepresentation: signature.copyBytes())

        let publicKey = try _RSA.Signing.PublicKey.init(pemRepresentation: "")
        return publicKey.isValidSignature(signature, for: digest)
    }
}
