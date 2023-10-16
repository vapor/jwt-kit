import Foundation
@_implementationOnly import CJWTKitBoringSSL

internal struct ECDSASigner: JWTAlgorithm, OpenSSLSigner {
    let key: ECDSAKey
    let algorithm: OpaquePointer
    let name: String
    
    var curveResultSize: Int {
        let curveName = CJWTKitBoringSSL_EC_GROUP_get_curve_name(CJWTKitBoringSSL_EC_KEY_get0_group(key.c))
        switch curveName {
        case NID_X9_62_prime256v1:
            return 32
        case  NID_secp384r1:
            return 48
        case NID_secp521r1:
            return 66
        default:
            fatalError("Unsupported ECDSA key curve: \(curveName)")
        }
    }

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)
        guard let signature = CJWTKitBoringSSL_ECDSA_do_sign(
            digest,
            numericCast(digest.count),
            self.key.c
        ) else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.signFailure)
        }
        defer { CJWTKitBoringSSL_ECDSA_SIG_free(signature) }

        // serialize r+s values
        // see: https://tools.ietf.org/html/rfc7515#appendix-A.3
        let r = CJWTKitBoringSSL_ECDSA_SIG_get0_r(signature)
        let s = CJWTKitBoringSSL_ECDSA_SIG_get0_s(signature)
        let rsSize = self.curveResultSize
        var rBytes = [UInt8](repeating: 0, count: rsSize)
        var sBytes = [UInt8](repeating: 0, count: rsSize)
        let rCount = Int(CJWTKitBoringSSL_BN_bn2bin(r, &rBytes))
        let sCount = Int(CJWTKitBoringSSL_BN_bn2bin(s, &sBytes))
        // zero-padding may be on wrong side after write
        return rBytes.prefix(rCount).zeroPrefixed(upTo: rsSize)
            + sBytes.prefix(sCount).zeroPrefixed(upTo: rsSize)
    }

    func verify<Signature, Plaintext>(
        _ signature: Signature,
        signs plaintext: Plaintext
    ) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)

        // parse r+s values
        // see: https://tools.ietf.org/html/rfc7515#appendix-A.3
        let signatureBytes = signature.copyBytes()
        let rsSize = self.curveResultSize
        guard signatureBytes.count == rsSize * 2 else {
            return false
        }

        let signature = CJWTKitBoringSSL_ECDSA_SIG_new()
        defer { CJWTKitBoringSSL_ECDSA_SIG_free(signature) }

        try signatureBytes.prefix(rsSize).withUnsafeBufferPointer { r in
            try signatureBytes.suffix(rsSize).withUnsafeBufferPointer { s in
                // passing bignums to this method transfers ownership
                // (they will be freed when the signature is freed)
                guard CJWTKitBoringSSL_ECDSA_SIG_set0(
                    signature,
                    CJWTKitBoringSSL_BN_bin2bn(r.baseAddress, rsSize, nil),
                    CJWTKitBoringSSL_BN_bin2bn(s.baseAddress, rsSize, nil)
                ) == 1 else {
                    throw JWTError.signingAlgorithmFailure(ECDSAError.signFailure)
                }
            }
        }

        return CJWTKitBoringSSL_ECDSA_do_verify(
            digest,
            numericCast(digest.count),
            signature,
            self.key.c
        ) == 1
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
