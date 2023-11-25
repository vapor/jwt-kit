import _CryptoExtras
import Foundation

struct RSASigner: JWTAlgorithm, CryptoSigner {
    enum Key {
        case `public`(RSA.PublicKey)
        case `private`(RSA.PrivateKey)
    }

    let key: Key
    var algorithm: DigestAlgorithm
    let name: String
    let padding: _RSA.Signing.Padding

    init(key: some RSAKey, algorithm: DigestAlgorithm, name: String, padding: _RSA.Signing.Padding) {
        switch key {
        case let key as RSA.PrivateKey:
            self.key = .private(key)
        case let key as RSA.PublicKey:
            self.key = .public(key)
        default:
            fatalError("Unexpected key type: \(type(of: key))")
        }
        self.algorithm = algorithm
        self.name = name
        self.padding = padding
    }

    func sign(_ plaintext: some DataProtocol) throws -> [UInt8] {
        guard case let .private(privateKey) = key else {
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

        switch key {
        case let .private(privateKey):
            return privateKey.publicKey.isValidSignature(signature, for: digest, padding: padding)
        case let .public(publicKey):
            return publicKey.isValidSignature(signature, for: digest, padding: padding)
        }
    }
}

extension _RSA.Signing.Padding: @unchecked Sendable {}
