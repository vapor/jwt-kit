import _CryptoExtras
import Crypto
import Foundation

struct RSASigner: JWTAlgorithm, CryptoSigner {
    let key: RSAKey
    var algorithm: DigestAlgorithm
    let name: String

    init(key: RSAKey, algorithm: DigestAlgorithm, name: String) {
        self.key = key
        self.algorithm = algorithm
        self.name = name
    }

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        guard
            case .private = key.type,
            let privateKey = key.privateKey
        else {
            throw JWTError.signingAlgorithmFailure(RSAError.privateKeyRequired)
        }

        let digest = try self.digest(plaintext)

        do {
            let signature = try privateKey.signature(for: digest)
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

        guard let publicKey = key.privateKey?.publicKey ?? key.publicKey else {
            throw JWTError.signingAlgorithmFailure(RSAError.publicKeyRequired)
        }
        return publicKey.isValidSignature(signature, for: digest)
    }
}
