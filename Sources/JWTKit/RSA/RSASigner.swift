import _CryptoExtras

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

struct RSASigner: JWTAlgorithm, CryptoSigner {
    let publicKey: Insecure.RSA.PublicKey
    let privateKey: Insecure.RSA.PrivateKey?
    var algorithm: DigestAlgorithm
    let name: String
    let padding: _RSA.Signing.Padding

    init(key: some RSAKey, algorithm: DigestAlgorithm, name: String, padding: _RSA.Signing.Padding) {
        switch key {
        case let key as Insecure.RSA.PrivateKey:
            self.privateKey = key
            self.publicKey = key.publicKey
        case let key as Insecure.RSA.PublicKey:
            self.publicKey = key
            self.privateKey = nil
        default:
            // This should never happen
            fatalError("Unexpected key type: \(type(of: key))")
        }
        self.algorithm = algorithm
        self.name = name
        self.padding = padding
    }

    func sign(_ plaintext: some DataProtocol) throws -> [UInt8] {
        guard let privateKey else {
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

        return publicKey.isValidSignature(signature, for: digest, padding: padding)
    }
}
