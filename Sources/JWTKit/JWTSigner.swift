import Foundation

/// A JWT signer.
final class JWTSigner: Sendable {
    let algorithm: JWTAlgorithm

    let jsonEncoder: (any JWTJSONEncoder)?
    let jsonDecoder: (any JWTJSONDecoder)?

    init(
        algorithm: JWTAlgorithm,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) {
        self.algorithm = algorithm
        self.jsonEncoder = jsonEncoder
        self.jsonDecoder = jsonDecoder
    }

    func sign(
        _ payload: some JWTPayload,
        with header: JWTHeader = JWTHeader(),
        using serializer: some JWTSerializer = DefaultJWTSerializer()
    ) async throws -> String {
        try await serializer.sign(
            payload,
            with: header,
            using: self.algorithm,
            jsonEncoder: self.jsonEncoder ?? .defaultForJWT
        )
    }

    func verify<Payload>(parser: some JWTParser) async throws -> Payload
        where Payload: JWTPayload
    {
        try parser.verify(using: algorithm)
        let payload = try parser.parsePayload(as: Payload.self, jsonDecoder: self.jsonDecoder ?? .defaultForJWT)
        try await payload.verify(using: algorithm)
        return payload
    }
}
