@_implementationOnly import CJWTKitBoringSSL
import Foundation

/// An object for verifying JWS tokens that contain the `x5c` header parameter
/// with a set of known root certificates.
///
/// Usage:
/// ```
/// let verifier = try X5CVerifier(rootCertificates: myRoots)
/// let payload = try verifier.verifyJWS(myJWS, as: MyPayload.self)
/// // payload is now known to be valid!
/// ```
///
/// See [RFC 7515](https://www.rfc-editor.org/rfc/rfc7515#section-4.1.6)
/// for details on the `x5c` header parameter.
public class X5CVerifier {
    private let trustedStore: X509TrustStore

    /// Create a new X5CVerifier trusting `rootCertificates`.
    ///
    /// - Parameter rootCertificates: The root certificates to be trusted.
    public convenience init(rootCertificates: [String]) throws {
        try self.init(rootCertificates: rootCertificates.map {
            Array($0.utf8)
        })
    }

    /// Create a new X5CVerifier trusting `rootCertificates`.
    ///
    /// - Parameter rootCertificates: The root certificates to be trusted.
    public init<Message: DataProtocol>(rootCertificates: [Message]) throws {
        guard !rootCertificates.isEmpty else {
            throw JWTError.generic(identifier: "JWS", reason: "No root certs provided")
        }
        trustedStore = try X509TrustStore()
        do {
            for rootCert in rootCertificates {
                let rootCertx509 = try X509Pointer(pem: rootCert)
                try trustedStore.trust(rootCertx509)
            }
        } catch {
            trustedStore.freeAll()
            throw error
        }
    }

    deinit {
        trustedStore.freeAll()
    }

    /// Verify a JWS with the `x5c` header parameter against the trusted root
    /// certificates.
    ///
    /// - Parameters:
    ///   - token: The JWS to verify.
    ///   - payload: The type to decode from the token payload.
    /// - Returns: The decoded payload, if verified.
    public func verifyJWS<Payload: JWTPayload>(
        _ token: String,
        as payload: Payload.Type = Payload.self
    ) throws -> Payload {
        try self.verifyJWS(Array(token.utf8), as: Payload.self)
    }

    /// Verify a JWS with `x5c` claims against the
    /// trusted root certificates.
    ///
    /// - Parameters:
    ///   - token: The JWS to verify.
    ///   - payload: The type to decode from the token payload.
    /// - Returns: The decoded payload, if verified.
    public func verifyJWS<Message, Payload>(
        _ token: Message,
        as payload: Payload.Type = Payload.self
    ) throws -> Payload
        where Message: DataProtocol, Payload: JWTPayload
    {
        let parser = try JWTParser(token: token)
        let header = try parser.header()

        guard let headerAlg = header.alg,
              headerAlg == "ES256" else {
            throw JWTError.generic(identifier: "JWS", reason: "Only ES256 is currently supported")
        }
        guard let x5c = header.x5c, !x5c.isEmpty else {
            throw JWTError.generic(identifier: "JWS", reason: "No x5c certificates provided")
        }


        // Setup an untrusted chain using all the certificates in the x5c.
        let untrustedChain = try X509Chain()
        defer { untrustedChain.freeAll() }

        for cert in x5c {
            let x509 = try X509Pointer(x5c: cert)
            try untrustedChain.push(x509)
        }

        // The first cert in x5c is used to sign the JWS, so that's what we're
        // targeting.
        let ctx = try X509StoreContext(
            trusting: trustedStore,
            targeting: untrustedChain[0]!, // We verify above that this isn't empty
            untrusted: untrustedChain
        )
        defer { ctx.free() }

        // Verify the x5c chain is valid.
        try ctx.verify()

        // Now that we know the chain is valid, we have
        // to verify that the token was signed with the
        // known-valid signing cert.

        let signingCert = x5c[0] // We verify above that this isn't empty
        let keyData = addBoundaryToCert(signingCert)
        let ecdsaKey = try ECDSAKey.certificate(pem: keyData)

        let signer = JWTSigner(
            algorithm: ECDSASigner(
                key: ecdsaKey,
                algorithm: CJWTKitBoringSSL_EVP_sha256(),
                name: headerAlg
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
    init<Message: DataProtocol>(pem cert: Message) throws {
        value = try ECDSAKey.load(pem: cert) { bio in
            CJWTKitBoringSSL_PEM_read_bio_X509(bio, nil, nil, nil)
        }
    }

    /// Read an x5c claim.
    init(x5c claim: String) throws {
        let pem = Array(addBoundaryToCert(claim).utf8)
        try self.init(pem: pem)
    }

    func free() {
        CJWTKitBoringSSL_X509_free(value)
    }
}

/// Wraps a CJWTKitBoringSSL `X509_STORE` pointer.
///
/// You must manually call `freeAll()`.
private struct X509TrustStore {
    var value: OpaquePointer

    init() throws {
        guard let trustedStore = CJWTKitBoringSSL_X509_STORE_new() else {
            throw JWTError.generic(identifier: "JWS", reason: "OpenSSL failure")
        }
        self.value = trustedStore
    }

    /// Add this certificate to the trust store.
    func trust(_ cert: X509Pointer) throws {
        guard  CJWTKitBoringSSL_X509_STORE_add_cert(value, cert.value) == 1 else {
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
        guard let value = CJWTKitBoringSSL_sk_X509_new_null() else {
            throw JWTError.generic(identifier: "JWS", reason: "OpenSSL failure")
        }
        self.value = value
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
        guard CJWTKitBoringSSL_sk_X509_push(value, x509.value) != 0 else {
            throw JWTError.generic(identifier: "JWS", reason: "Couldn't push cert")
        }
    }

    /// Get the X509 at the index (0-based).
    subscript(index: Int) -> X509Pointer? {
        return CJWTKitBoringSSL_sk_X509_value(value, index).map(X509Pointer.init(value:))
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
        guard CJWTKitBoringSSL_X509_verify_cert(value) == 1 else {
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
