@_implementationOnly import CJWTKitBoringSSL
import struct Foundation.Data
import _CryptoExtras

internal struct RSASigner2: JWTAlgorithm {

    let key: RSAKey2
    let name: String

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8] where Plaintext : DataProtocol {
        guard let privateKey = key.privateKeyBacking else {
            throw RSAError.privateKeyRequired
        }
        let bytes = try privateKey.signature(for: plaintext).rawRepresentation
        return Array(bytes)
    }

    func verify<Signature, Plaintext>(_ signature: Signature, signs plaintext: Plaintext) throws -> Bool where Signature : DataProtocol, Plaintext : DataProtocol {
        let publicKey: _RSA.Signing.PublicKey
        if let key = self.key.publicKeyBacking {
            publicKey = key
        } else if let key = self.key.privateKeyBacking?.publicKey {
            publicKey = key
        } else {
            // Something bad has gone wrong as we should be able to get into this state
            throw RSAError.keyInitializationFailure
        }
        let rsaSignature = _RSA.Signing.RSASignature(rawRepresentation: signature)
        return try publicKey.isValidSignature(rsaSignature, for: plaintext)
    }
}

internal struct RSASigner: JWTAlgorithm, OpenSSLSigner {
    let key: RSAKey
    let algorithm: OpaquePointer
    let name: String

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        guard case .private = self.key.type else {
            throw JWTError.signingAlgorithmFailure(RSAError.privateKeyRequired)
        }
        var signatureLength: UInt32 = 0
        var signature = [UInt8](
            repeating: 0,
            count: Int(CJWTKitBoringSSL_RSA_size(key.c))
        )

        let digest = try self.digest(plaintext)
        guard CJWTKitBoringSSL_RSA_sign(
            CJWTKitBoringSSL_EVP_MD_type(self.algorithm),
            digest,
            numericCast(digest.count),
            &signature,
            &signatureLength,
            self.key.c
        ) == 1 else {
            throw JWTError.signingAlgorithmFailure(RSAError.signFailure)
        }

        return .init(signature[0..<numericCast(signatureLength)])
    }

    func verify<Signature, Plaintext>(
        _ signature: Signature,
        signs plaintext: Plaintext
    ) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)
        let signature = signature.copyBytes()
        return CJWTKitBoringSSL_RSA_verify(
            CJWTKitBoringSSL_EVP_MD_type(self.algorithm),
            digest,
            numericCast(digest.count),
            signature,
            numericCast(signature.count),
            self.key.c
        ) == 1
    }
}
