import Foundation

public struct ECDSASigner: JWTAlgorithm, CryptoSigner {
    let key: any ECDSAKeyType
    let algorithm: DigestAlgorithm
    public let name: String

    public func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)
        guard let privateKey = key.privateKey else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.noPrivateKey)
        }
        let signature = try privateKey.signature(for: digest)
        return [UInt8](signature.rawRepresentation)
    }

    public func verify<Signature, Plaintext>(
        _ signature: Signature,
        signs plaintext: Plaintext
    ) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)
        guard let publicKey = key.publicKey ?? key.privateKey?.publicKey else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.noPublicKey)
        }
        return try publicKey.isValidSignature(signature, for: digest)
    }
}
