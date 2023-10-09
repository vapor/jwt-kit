import Foundation

struct ECDSASigner: JWTAlgorithm, CryptoSigner {
    let key: any ECDSAKey
    let algorithm: DigestAlgorithm
    let name: String

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

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)
        guard let privateKey = key.privateKey else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.noPrivateKey)
        }
        let signature = try privateKey.signature(for: digest)
        return signature.copyBytes()
    }

    func verify<Signature, Plaintext>(
        _ signature: Signature,
        signs plaintext: Plaintext
    ) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)
        guard let publicKey = key.publicKey ?? key.privateKey?.pubKey else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.noPublicKey)
        }
        guard let signature = signature as? Data else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.signFailure)
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
