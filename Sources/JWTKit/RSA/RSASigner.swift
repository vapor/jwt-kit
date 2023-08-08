import Foundation
import Crypto
import _CryptoExtras

internal struct RSASigner: JWTAlgorithm, CryptoSigner {
    let key: RSAKey
    var algorithm: DigestAlgorithm
    let name: String

    init(key: RSAKey, algorithm: DigestAlgorithm) {
        self.key = key
        self.algorithm = algorithm
        self.name = algorithm.name
    }

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8] 
        where Plaintext: DataProtocol 
    {
        guard 
            case .private = self.key.type,
            let privateKey = self.key.privateKey 
        else {
            throw JWTError.signingAlgorithmFailure(RSAError.privateKeyRequired)
        }

        do {
            let signature = try privateKey.signature(for: plaintext)
            return [UInt8](signature.rawRepresentation)
        } catch {
            throw JWTError.signingAlgorithmFailure(RSAError.signFailure(error))
        }

    }

    func verify<Signature, Plaintext>(_ signature: Signature, signs plaintext: Plaintext) throws -> Bool 
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)
        let signature = _RSA.Signing.RSASignature(rawRepresentation: signature)

        guard let publicKey = self.key.privateKey?.publicKey ?? self.key.publicKey else {
            throw JWTError.signingAlgorithmFailure(RSAError.publicKeyRequired)
        }
        return publicKey.isValidSignature(signature, for: digest)
    }
}
