import Foundation

struct ECDSASigner<Key: ECDSAKey>: JWTAlgorithm, CryptoSigner {
    let privateKey: ECDSA.PrivateKey<Key.Curve>?
    let publicKey: ECDSA.PublicKey<Key.Curve>
    let algorithm: DigestAlgorithm
    public let name: String

    init(key: Key, algorithm: DigestAlgorithm, name: String) {
        switch key {
        case let privateKey as ECDSA.PrivateKey<Key.Curve>:
            self.privateKey = privateKey
            self.publicKey = privateKey.publicKey
        case let publicKey as ECDSA.PublicKey<Key.Curve>:
            self.publicKey = publicKey
            self.privateKey = nil
        default:
            // This should never happen
            fatalError("Unexpected key type: \(type(of: key))")
        }
        self.algorithm = algorithm
        self.name = name
    }

    func sign(_ plaintext: some DataProtocol) throws -> [UInt8] {
        let digest = try self.digest(plaintext)
        guard let privateKey else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.noPrivateKey)
        }
        let signature = try privateKey.signature(for: digest)
        return [UInt8](signature.rawRepresentation)
    }

    public func verify(_ signature: some DataProtocol, signs plaintext: some DataProtocol) throws -> Bool {
        let digest = try self.digest(plaintext)
        return try publicKey.isValidSignature(signature, for: digest)
    }
}
