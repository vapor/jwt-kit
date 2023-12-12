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
public struct X5CVerifier: Sendable {
    private let trustedStore: X509.CertificateStore

    /// Create a new X5CVerifier trusting `rootCertificates`.
    ///
    /// - Parameter rootCertificates: The root certificates to be trusted.
    public init(rootCertificates: [String]) throws {
        guard !rootCertificates.isEmpty else {
            throw JWTError.invalidX5CChain(reason: "No root certificates provided")
        }
        trustedStore = try X509.CertificateStore(rootCertificates.map {
            try X509.Certificate(pemEncoded: $0)
        })
    }

    /// Create a new X5CVerifier trusting `rootCertificates`.
    ///
    /// - Parameter rootCertificates: The root certificates to be trusted.
    public init<Message: DataProtocol>(rootCertificates: [Message]) throws {
        try self.init(rootCertificates: rootCertificates.map {
            String(decoding: $0, as: UTF8.self)
        })
    }

    /// Verify a chain of certificates against the trusted root certificates.
    ///
    /// - Parameter certificates: The certificates to verify.
    /// - Throws: A `JWTError` if the chain is invalid.
    func verifyChain(certificates: [String]) async throws {
        let certificates = try certificates.map {
            try Certificate(pemEncoded: $0)
        }
        let untrustedChain = CertificateStore(certificates)
        var verifier = Verifier(rootCertificates: trustedStore) {
            RFC5280Policy(validationTime: Date())
        }
        let result = await verifier.validate(leafCertificate: certificates[0], intermediates: untrustedChain)
        if case let .couldNotValidate(failures) = result {
            throw JWTError.invalidX5CChain(reason: "\(failures)")
        }
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
    public func verifyJWS<Payload>(
        _ token: some DataProtocol,
        as _: Payload.Type = Payload.self
    ) async throws -> Payload
        where Payload: JWTPayload
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
    public func verifyJWS<Payload>(
        _ token: some DataProtocol,
        as _: Payload.Type = Payload.self,
        jsonDecoder: any JWTJSONDecoder
    ) async throws -> Payload
        where Payload: JWTPayload
    {
        // Parse the JWS header to get the header
        let parser = try DefaultJWTParser(token: token)
        let header = try parser.parseHeader(jsonDecoder: jsonDecoder)

        // Ensure the algorithm used is ES256, as it's the only supported one (for now)
        guard let headerAlg = header.alg?.asString, headerAlg == "ES256" else {
            throw JWTError.invalidX5CChain(reason: "Unsupported algorithm: \(String(describing: header.alg))")
        }

        // Ensure the x5c header parameter is present and not empty
        guard let x5c = try header.x5c?.asArray(of: String.self), !x5c.isEmpty else {
            throw JWTError.invalidX5CChain(reason: "Missing or empty x5c header parameter")
        }

        // Decode the x5c certificates
        let certificateData = try x5c.map {
            guard let data = Data(base64Encoded: $0) else {
                throw JWTError.invalidX5CChain(reason: "Invalid x5c certificate: \($0)")
            }
            return data
        }

        let certificates = try certificateData.map {
            try Certificate(derEncoded: [UInt8]($0))
        }

        // Setup an untrusted chain using the intermediate certificates
        let untrustedChain = CertificateStore(certificates.dropFirst().dropLast())

        let payload = try parser.parsePayload(as: Payload.self, jsonDecoder: jsonDecoder)

        let date: Date
        // Some JWT implementations have the sign date in the payload.
        // If it's such a payload, we'll use that date for validation
        if let validationTimePayload = payload as? ValidationTimePayload {
            date = validationTimePayload.signedDate
        } else {
            date = Date()
        }

        // Setup the verifier using the predefined trusted store
        var verifier = Verifier(rootCertificates: trustedStore) {
            RFC5280Policy(validationTime: date)
        }

        // Validate the leaf certificate against the trusted store
        let result = await verifier.validate(leafCertificate: certificates[0], intermediates: untrustedChain)

        if case let .couldNotValidate(failures) = result {
            throw JWTError.invalidX5CChain(reason: "\(failures)")
        }

        // Assuming the chain is valid, verify the token was signed by the valid certificate
        let ecdsaKey = try ES256PublicKey(certificate: certificates[0].serializeAsPEM().pemString)
        let signer = JWTSigner(algorithm: ECDSASigner(key: ecdsaKey, algorithm: .sha256, name: headerAlg))

        return try await signer.verify(parser: parser)
    }
}
