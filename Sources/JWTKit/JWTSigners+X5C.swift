@_implementationOnly import CJWTKitBoringSSL

extension JWTSigners {
    /// Verify a JWS with `x5c` claims.
    ///
    ///
    /// - Parameters:
    ///   - token: The JWS to verify.
    ///   - payload: The type to decode from the token payload.
    ///   - rootCert: The root certificate to trust when verifying `x5c`.
    /// - Returns: The decoded payload, if verified.
    public func verifyJWSWithX5C<Payload>(
        _ token: String,
        as payload: Payload.Type = Payload.self,
        rootCert: String
    ) throws -> Payload
        where Payload: JWTPayload
    {
        try self.verifyJWSWithX5C([UInt8](token.utf8), as: Payload.self, rootCert: [UInt8](rootCert.utf8))
    }

    /// Verify a JWS with `x5c` claims.
    ///
    ///
    /// - Parameters:
    ///   - token: The JWS to verify.
    ///   - payload: The type to decode from the token payload.
    ///   - rootCert: The root certificate to trust when verifying `x5c`.
    /// - Returns: The decoded payload, if verified.
    public func verifyJWSWithX5C<Message, Payload>(
        _ token: Message,
        as payload: Payload.Type = Payload.self,
        rootCert: Message
    ) throws -> Payload
        where Message: DataProtocol, Payload: JWTPayload
    {
        let parser = try JWTParser(token: token)
        let header = try parser.header()
        guard let x5c = header.x5c, !x5c.isEmpty else {
            throw JWTError.generic(identifier: "JWS", reason: "No x5c certificates provided")
        }

        guard header.alg == "ES256" else {
            throw JWTError.generic(identifier: "JWS", reason: "Only ES256 is currently supported")
        }

        // Verify the chain
        // The first cert is used to sign the JWS
        // Each subsequent cert should be used to certify the previous one
        // https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6

        let trustedStore = try X509TrustStore()
        defer { trustedStore.freeAll() }

        let rootCertx509 = try X509Pointer(pemECDSA: rootCert) // freed as part of the trusted store
        do {
            try trustedStore.trust(rootCertx509)
        } catch {
            // Won't be freed as part of trusted store
            // if it wasn't added! So manually free it here.
            rootCertx509.free()
            throw error
        }

        let untrustedChain = try X509Chain()
        defer { untrustedChain.freeAll() }

        for cert in x5c {
            // This looks like x509Chain = try x5c.map(X509Pointer.init(x5c:))
            // with a little push on the end, but note that
            // we have to call `.free()` on each allocated
            // cert. So it's not quite.
            let x509 = try X509Pointer(x5cECDSA: cert)
            try untrustedChain.push(x509)
        }

        let ctx = try X509StoreContext(
            trusting: trustedStore,
            targeting: untrustedChain[0]!, // We verify above that this isn't empty
            untrusted: untrustedChain
        )
        defer { ctx.free() }
        try ctx.verify()

        let signingCert = x5c[0] // We verify above that this isn't empty
        let keyData = addBoundaryToCert(signingCert)
        let ecdsaKey = try ECDSAKey.certificate(pem: keyData)

        let signer = JWTSigner(
            algorithm: ECDSASigner(
                key: ecdsaKey,
                algorithm: CJWTKitBoringSSL_EVP_sha256(),
                name: "ES256"
            )
        )
        return try signer.verify(parser: parser)
    }
}

/// Base64 DER format -> PEM format
private func addBoundaryToCert(_ cert: String) -> String {
    """
    -----BEGIN CERTIFICATE-----
    \(cert)
    -----END CERTIFICATE-----
    """
}

/// Wraps a CJWTKitBoringSSL X509 pointer.
///
/// You must manually call `free()`.
private struct X509Pointer {
    var value: OpaquePointer

    init(value: OpaquePointer) {
        self.value = value
    }

    /// Read a pem string.
    init<Message: DataProtocol>(pemECDSA cert: Message) throws {
        value = try ECDSAKey.load(pem: cert) { bio in
            CJWTKitBoringSSL_PEM_read_bio_X509(bio, nil, nil, nil)
        }
    }

    /// Read an x5c claim.
    init(x5cECDSA claim: String) throws {
        let pem = Array(addBoundaryToCert(claim).utf8)
        try self.init(pemECDSA: pem)
    }

    func free() {
        CJWTKitBoringSSL_X509_free(value)
    }
}

/// Wraps a CJWTKitBoringSSL `X509_STORE` pointer.
///
/// You must manually call `free()`.
private struct X509TrustStore {
    var value: OpaquePointer

    init() throws {
        let trustedStore = CJWTKitBoringSSL_X509_STORE_new()
        if let trustedStore = trustedStore {
            value = trustedStore
        } else {
            throw JWTError.generic(identifier: "JWS", reason: "OpenSSL failure")
        }
    }

    /// Add this certificate to the trust store.
    func trust(_ cert: X509Pointer) throws {
        if  CJWTKitBoringSSL_X509_STORE_add_cert(value, cert.value) != 1 {
            throw JWTError.generic(identifier: "JWS", reason: "Couldn't add cert")
        }
    }

    /// Frees this store AND anything in it. So don't call
    /// free on anything you've added to this.
    func freeAll() {
        CJWTKitBoringSSL_X509_STORE_free(value)
    }
}


/// Wraps a CJWTKitBoringSSL `STACK_OF(X509)`.
///
/// You must manually call `freeAll()`.
private struct X509Chain {
    var value: OpaquePointer

    init() throws {
        if let value = CJWTKitBoringSSL_sk_X509_new_null() {
            self.value = value
        } else {
            throw JWTError.generic(identifier: "JWS", reason: "OpenSSL failure")
        }
    }

    /// Frees this chain AND anything in it. So don't call
    /// free on anything you've added to this.
    func freeAll() {
        // For future maintainers:
        // There's also a `CJWTKitBoringSSL_sk_X509_free`
        // that just frees the stack and not the X509s
        // inside. That may be helpful to wrap.
        CJWTKitBoringSSL_sk_X509_pop_free(value, CJWTKitBoringSSL_X509_free)
    }

    func push(_ x509: X509Pointer) throws {
        if CJWTKitBoringSSL_sk_X509_push(value, x509.value) == 0 {
            throw JWTError.generic(identifier: "JWS", reason: "Couldn't push cert")
        }
    }

    /// Get the X509 at the index (0-based).
    subscript(index: Int) -> X509Pointer? {
        if let pointer = CJWTKitBoringSSL_sk_X509_value(value, index) {
            return X509Pointer(value: pointer)
        } else {
            return nil
        }
    }
}

/// Wraps a CJWTKitBoringSSL `X509_STORE_CTX`.
///
/// You must manually call `free()`.
private struct X509StoreContext {
    var value: OpaquePointer

    /// Creates a new context and initializes it.
    init(
        trusting: X509TrustStore,
        targeting: X509Pointer,
        untrusted: X509Chain
    ) throws {
        value = CJWTKitBoringSSL_X509_STORE_CTX_new()
        guard
            CJWTKitBoringSSL_X509_STORE_CTX_init(
                value,
                /*trusted=*/trusting.value,
                /*target=*/targeting.value,
                /*untrusted=*/untrusted.value
            ) == 1
        else {
            self.free()
            throw JWTError.generic(identifier: "JWS", reason: "Failed to init the ctx")
        }
    }

    func free() {
        CJWTKitBoringSSL_X509_STORE_CTX_free(value)
    }

    /// Verifies the context as currently built.
    func verify() throws {
        if CJWTKitBoringSSL_X509_verify_cert(value) != 1 {
            throw buildError()
        }
    }

    /// Create an error based on `X509_STORE_CTX_get_error`.
    private func buildError() -> Error {
        let errorCode =  CJWTKitBoringSSL_X509_STORE_CTX_get_error(value)
        // This string is never nil & is a constant; do not
        // attempt to free it.
        let errorCString = CJWTKitBoringSSL_X509_verify_cert_error_string(Int(errorCode))
        let errorString = String(cString: errorCString!)
        let depth = CJWTKitBoringSSL_X509_STORE_CTX_get_error_depth(value)
        return JWTError.generic(identifier: "JWS", reason: "Invalid x5c chain @ \(depth): \(errorString)")
    }
}
