import Foundation

/// A JWT signer.
public final class JWTSigner {
    public let algorithm: JWTAlgorithm

    public init(algorithm: JWTAlgorithm) {
        self.algorithm = algorithm
    }

    public func sign<Payload>(
        _ payload: Payload,
        typ: String = "JWT",
        kid: JWKIdentifier? = nil,
        cty: String? = nil
    ) throws -> String
        where Payload: JWTPayload
    {
        try JWTSerializer().sign(payload, using: self, typ: typ, kid: kid, cty: cty)
    }

    public func unverified<Payload>(
        _ token: String,
        as payload: Payload.Type = Payload.self
    ) throws -> Payload
        where Payload: JWTPayload
    {
        try self.unverified([UInt8](token.utf8))
    }

    public func unverified<Message, Payload>(
        _ token: Message,
        as payload: Payload.Type = Payload.self
    ) throws -> Payload
        where Message: DataProtocol, Payload: JWTPayload
    {
        try JWTParser(token: token).payload(as: Payload.self)
    }

    public func verify<Payload>(
        _ token: String,
        as payload: Payload.Type = Payload.self
    ) throws -> Payload
        where Payload: JWTPayload
    {
        try self.verify([UInt8](token.utf8), as: Payload.self)
    }

    public func verify<Message, Payload>(
        _ token: Message,
        as payload: Payload.Type = Payload.self
    ) throws -> Payload
        where Message: DataProtocol, Payload: JWTPayload
    {
        let parser = try JWTParser(token: token)
        return try self.verify(parser: parser)
    }

    func verify<Payload>(parser: JWTParser) throws -> Payload
        where Payload: JWTPayload
    {
        try parser.verify(using: self)
        let payload = try parser.payload(as: Payload.self)
        try payload.verify(using: self)
        return payload
    }
}
