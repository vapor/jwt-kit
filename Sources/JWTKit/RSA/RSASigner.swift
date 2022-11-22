@_implementationOnly import CJWTKitBoringSSL
import struct Foundation.Data

internal struct RSASigner: JWTAlgorithm, OpenSSLSigner {
    let key: RSAKey
    let algorithm: OpaquePointer
    let name: String
    let usePSS: Bool

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        guard case .private = self.key.type else {
            throw JWTError.signingAlgorithmFailure(RSAError.privateKeyRequired)
        }

        var signature = [UInt8](
            repeating: 0,
            count: Int(CJWTKitBoringSSL_RSA_size(key.c))
        )

        let digest = try self.digest(plaintext)
        let signingResult: Int32
        let signLen: Int
        if self.usePSS {
            var signatureLength: Int = 0
            signingResult = CJWTKitBoringSSL_RSA_sign_pss_mgf1(
                self.key.c,
                &signatureLength,
                &signature,
                signature.count,
                digest,
                numericCast(digest.count),
                self.algorithm,
                nil,
                -1)
            signLen = signatureLength
        } else {
            var signatureLength: UInt32 = 0
            signingResult = CJWTKitBoringSSL_RSA_sign(
                CJWTKitBoringSSL_EVP_MD_type(self.algorithm),
                digest,
                numericCast(digest.count),
                &signature,
                &signatureLength,
                self.key.c
            )
            signLen = numericCast(signatureLength)
        }
        guard signingResult == 1 else {
            throw JWTError.signingAlgorithmFailure(RSAError.signFailure)
        }

        return .init(signature[0..<numericCast(signLen)])
    }

    func verify<Signature, Plaintext>(
        _ signature: Signature,
        signs plaintext: Plaintext
    ) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)
        let signature = signature.copyBytes()
        if self.usePSS {
            return CJWTKitBoringSSL_RSA_verify_pss_mgf1(
                self.key.c,
                digest,
                digest.count,
                self.algorithm,
                nil,
                -1,
                signature,
                signature.count) == 1
        } else {
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
}
