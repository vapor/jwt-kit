import CJWTKitCrypto

internal struct ECDSASigner: JWTAlgorithm, OpenSSLSigner {
    let key: ECDSAKey
    let algorithm: OpaquePointer
    let name: String

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)
        guard let signature = ECDSA_do_sign(
            digest,
            numericCast(digest.count),
            self.key.c
        ) else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.signFailure)
        }
        defer { ECDSA_SIG_free(signature) }

        // serialize r+s values
        // see: https://tools.ietf.org/html/rfc7515#appendix-A.3
        var rBytes = [UInt8](repeating: 0, count: 32)
        var sBytes = [UInt8](repeating: 0, count: 32)
        let rCount = Int(BN_bn2bin(jwtkit_ECDSA_SIG_get0_r(signature), &rBytes))
        let sCount = Int(BN_bn2bin(jwtkit_ECDSA_SIG_get0_s(signature), &sBytes))

        // BN_bn2bin can return < 32 bytes which will result in the data
        // being zero-padded on the wrong side
        return .init(
            [UInt8](repeating: 0, count: 32 - rCount) +
            rBytes[0..<rCount] +
            [UInt8](repeating: 0, count: 32 - sCount) +
            sBytes[0..<sCount]
        )
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
        guard signatureBytes.count == 64 else {
            return false
        }

        let signature = ECDSA_SIG_new()
        defer { ECDSA_SIG_free(signature) }

        try signatureBytes[0..<32].withUnsafeBufferPointer { r in
            try signatureBytes[32..<64].withUnsafeBufferPointer { s in
                // passing bignums to this method transfers ownership
                // (they will be freed when the signature is freed)
                guard jwtkit_ECDSA_SIG_set0(
                    signature,
                    BN_bin2bn(r.baseAddress, 32, nil),
                    BN_bin2bn(s.baseAddress, 32, nil)
                ) == 1 else {
                    throw JWTError.signingAlgorithmFailure(ECDSAError.signFailure)
                }
            }
        }

        return ECDSA_do_verify(
            digest,
            numericCast(digest.count),
            signature,
            self.key.c
        ) == 1
    }
}
