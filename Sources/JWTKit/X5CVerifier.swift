import Foundation
import SwiftASN1
import X509

/// An object for verifying JWS tokens that contain the `x5c` header parameter
/// with a set of known root certificates.
///
/// Usage:
/// ```
/// let verifier = try X5CVerifier(rootCertificates: myRoots)
/// let payload = try await verifier.verifyJWS(myJWS, as: MyPayload.self)
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
        // Parse the JWS header to get the header
        let parser = try JWTParser(token: token)
        let header = try parser.header(jsonDecoder: jsonDecoder)

        // Ensure the algorithm used is ES256, as it's the only supported one (for now)
        guard let headerAlg = header.alg, headerAlg == "ES256" else {
            throw JWTError.generic(identifier: "JWS", reason: "Only ES256 is currently supported")
        }

        // Ensure the x5c header parameter is present and not empty
        guard let x5c = header.x5c, !x5c.isEmpty else {
            throw JWTError.generic(identifier: "JWS", reason: "No x5c certificates provided")
        }

        // Decode the x5c certificates
        let certificateData = try x5c.map {
            guard let data = Data(base64Encoded: $0) else {
                throw JWTError.generic(identifier: "JWS", reason: "Invalid x5c certificate")
            }
            return data
        }

        // Setup an untrusted chain using all the certificates in the x5c.
        let untrustedChain = try CertificateStore(certificateData.map {
            try Certificate(derEncoded: [UInt8]($0))
        })

        // Setup the verifier using the predefined trusted store
        var verifier = Verifier(rootCertificates: trustedStore) { RFC5280Policy(validationTime: Date()) }

        // Extract the leaf certificate (first certificate in x5c)
        let leafCertificate = try Certificate(derEncoded: [UInt8](certificateData[0]))

        // Validate the leaf certificate against the trusted store
        let result = await verifier.validate(leafCertificate: leafCertificate, intermediates: untrustedChain)

        if case let .couldNotValidate(failures) = result {
            throw JWTError.generic(identifier: "JWS", reason: "Invalid x5c chain: \(failures)")
        }

        // Assuming the chain is valid, verify the token was signed by the valid certificate.
        let ecdsaKey = try P256Key.certificate(pem: leafCertificate.serializeAsPEM().pemString)

        let signer = JWTSigner(algorithm: ECDSASigner(key: ecdsaKey, algorithm: .sha256, name: headerAlg))
        return try signer.verify(parser: parser)
    }
}
