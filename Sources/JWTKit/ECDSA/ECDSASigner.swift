import Foundation

public struct ECDSASigner: JWTAlgorithm, CryptoSigner {
    let key: any ECDSAKeyType
    let algorithm: DigestAlgorithm
    public let name: String

    var curveResultSize: Int {
        switch key.curve {
        case .p256:
            return 32
        case .p384:
            return 48
        case .p521:
            return 66
        default:
            fatalError("Unsupported ECDSA key curve: \(key)")
        }
    }

    public func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)
        guard let privateKey = key.privateKey else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.noPrivateKey)
        }
        let signature = try privateKey.signature(for: digest)
        return [UInt8](signature)
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

private extension Collection where Element == UInt8 {
    func zeroPrefixed(upTo count: Int) -> [UInt8] {
        if self.count < count {
            return [UInt8](repeating: 0, count: count - self.count) + self
        } else {
            return .init(self)
        }
    }
}
