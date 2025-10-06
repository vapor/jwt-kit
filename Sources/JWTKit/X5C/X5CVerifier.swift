import X509

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

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
    /// - Throws: ``JWTError/invalidX5CChain(reason:)`` if no root certificates are provided.
    public init(rootCertificates: [Certificate]) throws {
        guard !rootCertificates.isEmpty else {
            throw JWTError.invalidX5CChain(reason: "No root certificates provided")
        }
        trustedStore = X509.CertificateStore(rootCertificates)
    }

    /// Create a new X5CVerifier trusting `rootCertificates`.
    ///
    /// - Parameter rootCertificates: The root certificates to be trusted.
    /// - Throws: ``JWTError/invalidX5CChain(reason:)`` if no root certificates are provided.
    public init(rootCertificates: [String]) throws {
        guard !rootCertificates.isEmpty else {
            throw JWTError.invalidX5CChain(reason: "No root certificates provided")
        }
        try self.init(rootCertificates: rootCertificates.map { try X509.Certificate(pemEncoded: $0) })
    }

    /// Create a new X5CVerifier trusting `rootCertificates`.
    ///
    /// - Parameter rootCertificates: The root certificates to be trusted.
    /// - Throws: ``JWTError/invalidX5CChain(reason:)`` if no root certificates are provided.
    public init(rootCertificates: [some DataProtocol]) throws {
        guard !rootCertificates.isEmpty else {
            throw JWTError.invalidX5CChain(reason: "No root certificates provided")
        }
        try self.init(rootCertificates: rootCertificates.map { try X509.Certificate(derEncoded: [UInt8]($0)) })
    }

    /// Verify a chain of certificates against the trusted root certificates.
    ///
    /// - Parameter certificates: The certificates to verify.
    /// - Returns: A `X509.VerificationResult` indicating the result of the verification.
    public func verifyChain(
        certificates: [String],
        policy: () throws -> some VerifierPolicy = { RFC5280Policy(validationTime: Date()) }
    ) async throws -> X509.VerificationResult {
        let certificates = try certificates.map { try Certificate(pemEncoded: $0) }
        return try await verifyChain(certificates: certificates, policy: policy)
    }

    /// Verify a chain of certificates against the trusted root certificates.
    ///
    /// - Parameters:
    ///  - certificates: The certificates to verify.
    ///  - policy: The policy to use for verification.
    /// - Returns: A `X509.VerificationResult` indicating the result of the verification.
    public func verifyChain(
        certificates: [Certificate],
        @PolicyBuilder policy: () throws -> some VerifierPolicy = { RFC5280Policy(validationTime: Date()) }
    ) async throws -> X509.VerificationResult {
        let untrustedChain = CertificateStore(certificates)
        var verifier = try Verifier(rootCertificates: trustedStore, policy: policy)
        let result = await verifier.validate(
            leafCertificate: certificates[0], intermediates: untrustedChain)
        return result
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
    where Payload: JWTPayload {
        try await verifyJWS(token, as: Payload.self, jsonDecoder: .defaultForJWT)
    }

    /// Verify a JWS with `x5c` claims against the
    /// trusted root certificates, overriding the default JSON decoder.
    ///
    /// - Parameters:
    ///   - token: The JWS to verify.
    ///   - payload: The type to decode from the token payload.
    ///   - jsonDecoder: The JSON decoder to use for dcoding the token.
    ///   - policy: The policy to use for verification.
    /// - Returns: The decoded payload, if verified.
    public func verifyJWS<Payload>(
        _ token: some DataProtocol,
        as _: Payload.Type = Payload.self,
        jsonDecoder: any JWTJSONDecoder,
        @PolicyBuilder policy: () throws -> some VerifierPolicy = { RFC5280Policy(validationTime: Date()) }
    ) async throws -> Payload
    where Payload: JWTPayload {
        // Parse the JWS header to get the header
        let parser = DefaultJWTParser(jsonDecoder: jsonDecoder)
        let (header, payload, _) = try parser.parse(token, as: Payload.self)

        // Ensure the algorithm used is ES256, as it's the only supported one (for now)
        guard let headerAlg = header.alg, headerAlg == "ES256" else {
            throw JWTError.invalidX5CChain(reason: "Unsupported algorithm: \(String(describing: header.alg))")
        }

        // Ensure the x5c header parameter is present and not empty
        guard let x5c = header.x5c, !x5c.isEmpty else {
            throw JWTError.missingX5CHeader
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
        let untrustedChain = CertificateStore(certificates.dropFirst())

        let date: Date
        // Some JWT implementations have the sign date in the payload.
        // If it's such a payload, we'll use that date for validation
        if let validationTimePayload = payload as? ValidationTimePayload {
            date = validationTimePayload.signedDate
        } else {
            date = Date()
        }

        // Setup the verifier using the predefined trusted store
        var verifier = try Verifier(
            rootCertificates: trustedStore,
            policy: {
                try policy()
                RFC5280Policy(validationTime: date)
            })

        // Validate the leaf certificate against the trusted store
        let result = await verifier.validate(
            leafCertificate: certificates[0],
            intermediates: untrustedChain
        )

        if case .couldNotValidate(let failures) = result {
            throw JWTError.invalidX5CChain(reason: "\(failures)")
        }

        // Assuming the chain is valid, verify the token was signed by the valid certificate
        let ecdsaKey = try ES256PublicKey(certificate: certificates[0].serializeAsPEM().pemString)
        let signer = JWTSigner(algorithm: ECDSASigner(key: ecdsaKey), parser: parser)

        return try await signer.verify(token)
    }
}
