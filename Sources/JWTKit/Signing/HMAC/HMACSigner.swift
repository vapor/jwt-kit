import CJWTKitBoringSSL

internal struct HMACSigner: JWTAlgorithm {
    let key: [UInt8]
    let algorithm: OpaquePointer
    let name: String

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        let context = CJWTKitBoringSSL_HMAC_CTX_new()
        defer { CJWTKitBoringSSL_HMAC_CTX_free(context) }

        guard self.key.withUnsafeBytes({
            return CJWTKitBoringSSL_HMAC_Init_ex(context, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count, self.algorithm, nil)
        }) == 1 else {
            throw JWTError.signingAlgorithmFailure(HMACError.initializationFailure)
        }

        guard plaintext.copyBytes().withUnsafeBytes({
            return CJWTKitBoringSSL_HMAC_Update(context, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), $0.count)
        }) == 1 else {
            throw JWTError.signingAlgorithmFailure(HMACError.updateFailure)
        }
        var hash = [UInt8](repeating: 0, count: Int(EVP_MAX_MD_SIZE))
        var count: UInt32 = 0

        guard hash.withUnsafeMutableBytes({
            return CJWTKitBoringSSL_HMAC_Final(context, $0.baseAddress?.assumingMemoryBound(to: UInt8.self), &count)
        }) == 1 else {
            throw JWTError.signingAlgorithmFailure(HMACError.finalizationFailure)
        }
        return .init(hash[0..<Int(count)])
    }
}
