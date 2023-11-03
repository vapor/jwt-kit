import _CryptoExtras
import Crypto
import Foundation

struct RSASigner: JWTAlgorithm, CryptoSigner {
    let key: RSAKey
    var algorithm: DigestAlgorithm
    let name: String
    let padding: _RSA.Signing.Padding

    init(key: RSAKey, algorithm: DigestAlgorithm, name: String, padding: _RSA.Signing.Padding) {
        self.key = key
        self.algorithm = algorithm
        self.name = name
        self.padding = padding
    }

    func sign(_ plaintext: some DataProtocol) throws -> [UInt8] {
        guard
            case .private = key.type,
            let privateKey = key.privateKey
        else {
            throw JWTError.signingAlgorithmFailure(RSAError.privateKeyRequired)
        }

        let digest = try self.digest(plaintext)

        do {
            let signature = try privateKey.signature(for: digest, padding: padding)
            return [UInt8](signature.rawRepresentation)
        } catch {
            throw JWTError.signingAlgorithmFailure(RSAError.signFailure(error))
        }
    }

    func verify(_ signature: some DataProtocol, signs plaintext: some DataProtocol) throws -> Bool {
        let digest = try self.digest(plaintext)
        let signature = _RSA.Signing.RSASignature(rawRepresentation: signature)

        guard let publicKey = key.privateKey?.publicKey ?? key.publicKey else {
            throw JWTError.signingAlgorithmFailure(RSAError.publicKeyRequired)
        }
        return publicKey.isValidSignature(signature, for: digest, padding: padding)
    }
}
