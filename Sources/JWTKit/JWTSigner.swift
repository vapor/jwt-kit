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
        typ: String = "JWT",
        kid: JWKIdentifier? = nil,
        cty: String? = nil,
        x5c: [String]? = nil,
        customFields: [String: JWTHeaderField]? = nil
    ) async throws -> String {
        try await JWTSerializer().sign(
            payload,
            using: self,
            typ: typ,
            kid: kid,
            cty: cty,
            x5c: x5c,
            customFields: customFields,
            jsonEncoder: self.jsonEncoder ?? .defaultForJWT
        )
    }

    func unverified<Payload>(
        _ token: String,
        as _: Payload.Type = Payload.self
    ) throws -> Payload
        where Payload: JWTPayload
    {
        try self.unverified([UInt8](token.utf8))
    }

    func unverified<Payload>(
        _ token: some DataProtocol,
        as _: Payload.Type = Payload.self
    ) throws -> Payload
        where Payload: JWTPayload
    {
        try JWTParser(token: token).payload(as: Payload.self, jsonDecoder: self.jsonDecoder ?? .defaultForJWT)
    }

    func verify<Payload>(
        _ token: String,
        as _: Payload.Type = Payload.self
    ) async throws -> Payload
        where Payload: JWTPayload
    {
        try await self.verify([UInt8](token.utf8), as: Payload.self)
    }

    func verify<Payload>(
        _ token: some DataProtocol,
        as _: Payload.Type = Payload.self
    ) async throws -> Payload
        where Payload: JWTPayload
    {
        let parser = try JWTParser(token: token)
        return try await self.verify(parser: parser)
    }

    func verify<Payload>(parser: JWTParser) async throws -> Payload
        where Payload: JWTPayload
    {
        try parser.verify(using: algorithm)
        let payload = try parser.payload(as: Payload.self, jsonDecoder: self.jsonDecoder ?? .defaultForJWT)
        try await payload.verify(using: algorithm)
        return payload
    }
}
