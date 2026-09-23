#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

/// A JWT signer.
final class JWTSigner: Sendable {
    let algorithm: any JWTAlgorithm

    let parser: any JWTParser
    let serializer: any JWTSerializer

    init(
        algorithm: some JWTAlgorithm,
        parser: any JWTParser = DefaultJWTParser(),
        serializer: any JWTSerializer = DefaultJWTSerializer()
    ) {
        self.algorithm = algorithm
        self.parser = parser
        self.serializer = serializer
    }

    func sign(_ payload: some JWTPayload, with header: JWTHeader = .init()) async throws -> String {
        try await serializer.sign(payload, with: header, using: self.algorithm)
    }

    func verify<Payload>(_ token: some DataProtocol) async throws -> Payload where Payload: JWTPayload {
        try await verify(TokenParts(Array(token)))
    }

    func verify<Payload>(_ parts: TokenParts) async throws -> Payload where Payload: JWTPayload {
        let signature = try parts.signature.span.base64URLDecodedBytes()

        guard try algorithm.verify(signature, signs: parts.signingInput) else {
            throw JWTError.signatureVerificationFailed
        }

        let payload: Payload
        if let defaultParser = parser as? DefaultJWTParser {
            payload = try defaultParser.parsePayload(parts.payload, as: Payload.self)
        } else {
            // Custom parsers only see the whole token, which we still have.
            payload = try parser.parse(parts.token, as: Payload.self).payload
        }

        try await payload.verify(using: algorithm)
        return payload
    }
}
