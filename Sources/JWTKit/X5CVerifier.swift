import Foundation
import SwiftASN1
import X509

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
    private let trustedStore: X509.CertificateStore

    /// Create a new X5CVerifier trusting `rootCertificates`.
    ///
    /// - Parameter rootCertificates: The root certificates to be trusted.
    public init(rootCertificates: [String]) throws {
        guard !rootCertificates.isEmpty else {
            throw JWTError.generic(identifier: "JWS", reason: "No root certs provided")
        }
        trustedStore = try X509.CertificateStore(rootCertificates.map {
            try X509.Certificate(pemEncoded: $0)
        })
    }

    /// Create a new X5CVerifier trusting `rootCertificates`.
    ///
    /// - Parameter rootCertificates: The root certificates to be trusted.
    public convenience init<Message: DataProtocol>(rootCertificates: [Message]) throws {
        try self.init(rootCertificates: rootCertificates.map {
            String(decoding: $0, as: UTF8.self)
        })
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
        as _: Payload.Type = Payload.self
    ) async throws -> Payload {
        try await verifyJWS(token, as: Payload.self, jsonDecoder: .defaultForJWT)
    }

    /// Verify a JWS with the `x5c` header parameter against the trusted root
    /// certificates, overriding the default JSON decoder.
    ///
    /// - Parameters:
    ///   - token: The JWS to verify.
    ///   - payload: The type to decode from the token payload.
    ///   - jsonDecoder: The JSON decoder to use for decoding the token.
    /// - Returns: The decoded payload, if verified.
    public func verifyJWS<Payload: JWTPayload>(
        _ token: String,
        as _: Payload.Type = Payload.self,
        jsonDecoder: any JWTJSONDecoder
    ) async throws -> Payload {
        try await verifyJWS(Array(token.utf8), as: Payload.self, jsonDecoder: jsonDecoder)
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
        as _: Payload.Type = Payload.self
    ) async throws -> Payload
        where Message: DataProtocol, Payload: JWTPayload
    {
        try await verifyJWS(token, as: Payload.self, jsonDecoder: .defaultForJWT)
    }

    /// Verify a JWS with `x5c` claims against the
    /// trusted root certificates, overriding the default JSON decoder.
    ///
    /// - Parameters:
    ///   - token: The JWS to verify.
    ///   - payload: The type to decode from the token payload.
    ///   - jsonDecoder: The JSON decoder to use for dcoding the token.
    /// - Returns: The decoded payload, if verified.
    public func verifyJWS<Message, Payload>(
        _ token: Message,
        as _: Payload.Type = Payload.self,
        jsonDecoder: any JWTJSONDecoder
    ) async throws -> Payload
        where Message: DataProtocol, Payload: JWTPayload
    {
        let parser = try JWTParser(token: token)
        let header = try parser.header(jsonDecoder: jsonDecoder)

        guard
            let headerAlg = header.alg,
            headerAlg == "ES256"
        else {
            throw JWTError.generic(identifier: "JWS", reason: "Only ES256 is currently supported")
        }
        guard
            let x5c = header.x5c,
            !x5c.isEmpty
        else {
            throw JWTError.generic(identifier: "JWS", reason: "No x5c certificates provided")
        }

        let certificateData = try x5c.map {
            guard let data = Data(base64Encoded: $0) else {
                throw JWTError.generic(identifier: "JWS", reason: "Invalid x5c certificate")
            }
            return data
        }

        // Setup an untrusted chain using all the certificates in the x5c.
        let untrustedChain = try UnverifiedCertificateChain(certificateData.map {
            try Certificate(derEncoded: [UInt8]($0))
        })

        var verifier = Verifier(rootCertificates: trustedStore) { RFC5280Policy(validationTime: Date()) }

        // The first cert in x5c is used to sign the JWS, so that's what we're targeting.
        let result = await verifier.validate(leafCertificate: untrustedChain[0], intermediates: trustedStore)

        switch result {
        case let .validCertificate(certificateChain):
            print("Certificate is valid: \(certificateChain)")
        case let .couldNotValidate(failures):
            throw JWTError.generic(identifier: "JWS", reason: "Invalid x5c chain: \(failures)")
        }

        // Now that we know the chain is valid, we have
        // to verify that the token was signed with the
        // known-valid signing cert.

        let signingCert = x5c[0] // We verify above that this isn't empty
        let keyData = addBoundaryToCert(signingCert)
        let ecdsaKey = try P256Key.certificate(pem: keyData)

        let signer = JWTSigner(
            algorithm: ECDSASigner(
                key: ecdsaKey,
                algorithm: .sha256,
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

// /// Wraps a CJWTKitBoringSSL X509 pointer.
// ///
// /// You must manually call `free()`.
// private struct X509Pointer {
//     var certificate: X509.Certificate

//     /// Read a pem string.
//     init<Message: DataProtocol>(pem cert: Message) throws {
//         let string = String(decoding: cert, as: UTF8.self)
//         certificate = try X509.Certificate(pemEncoded: string)
//     }

//     /// Read an x5c claim.
//     init(x5c claim: String) throws {
//         certificate = try X509.Certificate(pemEncoded: claim)
//     }
// }

// private struct X509TrustStore {
//     private var trustedCertificates: [X509.Certificate]

//     init(trustedCertificates: [X509.Certificate] = []) {
//         self.trustedCertificates = trustedCertificates
//     }

//     /// Add this certificate to the trust store.
//     mutating func trust(_ certificate: X509.Certificate) {
//         trustedCertificates.append(certificate)
//     }
// }

/// Wraps a CJWTKitBoringSSL `STACK_OF(X509)`.
///
/// You must manually call `freeAll()`.
// private struct X509Chain {
//     var certificates: [X509.Certificate]

//     init() {
//         certificates = []
//     }

//     mutating func push(_ certificate: X509.Certificate) {
//         certificates.append(certificate)
//     }

//     /// Get the X509 at the index (0-based).
//     subscript(index: Int) -> X509.Certificate? {
//         guard
//             index >= 0,
//             index < certificates.count
//         else {
//             return nil
//         }
//         return certificates[index]
//     }
// }
