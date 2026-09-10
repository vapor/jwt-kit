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
        let (encodedHeader, encodedPayload, encodedSignature) = try parser.getTokenParts(token)
        return try await verify(encodedHeader: encodedHeader, encodedPayload: encodedPayload, encodedSignature: encodedSignature)
    }

    func verify<Payload>(
        encodedHeader: ArraySlice<UInt8>,
        encodedPayload: ArraySlice<UInt8>,
        encodedSignature: ArraySlice<UInt8>
    ) async throws -> Payload where Payload: JWTPayload {
        let data = encodedHeader + [.period] + encodedPayload
        let signature = encodedSignature.base64URLDecodedBytes()

        guard try algorithm.verify(signature, signs: data) else {
            throw JWTError.signatureVerificationFailed
        }

        let payload: Payload
        if let defaultParser = parser as? DefaultJWTParser {
            payload = try defaultParser.parsePayload(encodedPayload, as: Payload.self)
        } else {
            // We have to rebuild it here to use custom parsers
            // but most people won't have a custom parser anyway
            let wholeToken = data + [.period] + encodedSignature
            payload = try parser.parse(wholeToken, as: Payload.self).payload
        }

        try await payload.verify(using: algorithm)
        return payload
    }
}
