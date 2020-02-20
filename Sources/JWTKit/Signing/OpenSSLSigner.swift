import CVaporJWTBoringSSL

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
        let context = CVaporJWTBoringSSL_EVP_MD_CTX_new()
        defer { CVaporJWTBoringSSL_EVP_MD_CTX_free(context) }

        guard CVaporJWTBoringSSL_EVP_DigestInit_ex(context, convert(self.algorithm), nil) == 1 else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.digestInitializationFailure)
        }
        let plaintext = plaintext.copyBytes()
        guard CVaporJWTBoringSSL_EVP_DigestUpdate(context, plaintext, plaintext.count) == 1 else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.digestUpdateFailure)
        }
        var digest: [UInt8] = .init(repeating: 0, count: Int(EVP_MAX_MD_SIZE))
        var digestLength: UInt32 = 0

        guard CVaporJWTBoringSSL_EVP_DigestFinal_ex(context, &digest, &digestLength) == 1 else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.digestFinalizationFailure)
        }
        return .init(digest[0..<Int(digestLength)])
    }
}

protocol OpenSSLKey { }

extension OpenSSLKey {
    static func load<Data, T>(pem data: Data, _ closure: (OpaquePointer) -> (T?)) throws -> T
        where Data: DataProtocol
    {
        let bio = CVaporJWTBoringSSL_BIO_new(CVaporJWTBoringSSL_BIO_s_mem())
        defer { CVaporJWTBoringSSL_BIO_free(bio) }

        guard (data.copyBytes() + [0]).withUnsafeBytes({ pointer in
            CVaporJWTBoringSSL_BIO_puts(bio, pointer.baseAddress?.assumingMemoryBound(to: Int8.self))
        }) >= 0 else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.bioPutsFailure)
        }

        guard let c = closure(convert(bio!)) else {
            throw JWTError.signingAlgorithmFailure(OpenSSLError.bioConversionFailure)
        }
        return c
    }
}
