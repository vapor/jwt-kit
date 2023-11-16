import Foundation

struct ECDSASigner: JWTAlgorithm, CryptoSigner {
    let key: any ECDSAKeyType
    let algorithm: DigestAlgorithm
    public let name: String

    func sign(_ plaintext: some DataProtocol) throws -> [UInt8] {
        let digest = try self.digest(plaintext)
        guard let privateKey = key.privateKey else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.noPrivateKey)
        }
        let signature = try privateKey.signature(for: digest)
        return [UInt8](signature.rawRepresentation)
    }

    public func verify(_ signature: some DataProtocol, signs plaintext: some DataProtocol) throws -> Bool {
        let digest = try self.digest(plaintext)
        return try key.publicKey.isValidSignature(signature, for: digest)
    }
}
