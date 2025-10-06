#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

/// A JWT signer.
final class JWTSigner: Sendable {
    let algorithm: JWTAlgorithm

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
        let (encodedHeader, encodedPayload, encodedSignature) = try parser.getTokenParts(token)
        let data = encodedHeader + [.period] + encodedPayload
        let signature = encodedSignature.base64URLDecodedBytes()

        guard try algorithm.verify(signature, signs: data) else {
            throw JWTError.signatureVerificationFailed
        }

        let (_, payload, _) = try parser.parse(token, as: Payload.self)

        try await payload.verify(using: algorithm)
        return payload
    }
}
