import Foundation
@_implementationOnly import CJWTKitBoringSSL

protocol OpenSSLSigner {
    var algorithm: OpaquePointer { get }
}

private enum OpenSSLError: Error {
    case digestInitializationFailure
    case digestUpdateFailure
    case digestFinalizationFailure
    case bioPutsFailure
    case bioConversionFailure
}

extension OpenSSLSigner {
    func digest<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        let context = CJWTKitBoringSSL_EVP_MD_CTX_new()
        defer { CJWTKitBoringSSL_EVP_MD_CTX_free(context) }

        guard CJWTKitBoringSSL_EVP_DigestInit_ex(context, self.algorithm, nil) == 1 else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.digestInitializationFailure)
        }
        let plaintext = plaintext.copyBytes()
        guard CJWTKitBoringSSL_EVP_DigestUpdate(context, plaintext, plaintext.count) == 1 else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.digestUpdateFailure)
        }
        var digest: [UInt8] = .init(repeating: 0, count: Int(EVP_MAX_MD_SIZE))
        var digestLength: UInt32 = 0

        guard CJWTKitBoringSSL_EVP_DigestFinal_ex(context, &digest, &digestLength) == 1 else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.digestFinalizationFailure)
        }
        return .init(digest[0..<Int(digestLength)])
    }
}

protocol OpenSSLKey { }

extension OpenSSLKey {
    static func load<Data, T>(pem data: Data, _ closure: (UnsafeMutablePointer<BIO>) -> (T?)) throws -> T
        where Data: DataProtocol
    {
        let bytes = data.copyBytes()
        let bio = CJWTKitBoringSSL_BIO_new_mem_buf(bytes, numericCast(bytes.count))
        defer { CJWTKitBoringSSL_BIO_free(bio) }
        
        guard let bioPtr = bio, let c = closure(bioPtr) else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.bioConversionFailure)
        }
        return c
    }
}
