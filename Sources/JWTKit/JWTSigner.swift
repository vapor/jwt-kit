/// A JWT signer.
public final class JWTSigner {
    public let algorithm: JWTAlgorithm

    /// Set up the signer with a given algorithm.
    public init(algorithm: JWTAlgorithm) {
        self.algorithm = algorithm
    }

    /// Signs a JWT with a given payload and appropriate header values.
    /// - Parameters:
    ///   - payload: The JWT's payload type. Must conform to `JWTPayload`.
    ///   - typ: The signature's content type. Defaults to "JWT".
    ///   - kid: The key ID for the token (if any).
    ///   - cty: The payload's content type (if any).
    ///   - zip: The compression type to use for the payload (if any).
    public func sign<Payload: JWTPayload>(
        _ payload: Payload,
        typ: String = "JWT",
        kid: JWKIdentifier? = nil,
        cty: String? = nil,
        zip: CompressionType? = nil
    ) throws -> String {
        try JWTSerializer().sign(payload, using: self, typ: typ, kid: kid, cty: cty, zip: zip)
    }

    /// Parses a given token without verifying it.
    /// - Parameters:
    ///   - token: The string containing the encoded token.
    ///   - payload: The type to parse the payload as. Must conform to `JWTPayload`.
    public func unverified<Payload: JWTPayload>(
        _ token: String,
        as payload: Payload.Type = Payload.self
    ) throws -> Payload {
        try self.unverified([UInt8](token.utf8))
    }

    /// Parses a given token without verifying it.
    /// - Parameters:
    ///   - token: The instance of `DataProtocol` containing the encoded token.
    ///   - payload: The type to parse the payload as. Must conform to `JWTPayload`.
    public func unverified<Message: DataProtocol, Payload: JWTPayload>(
        _ token: Message,
        as payload: Payload.Type = Payload.self
    ) throws -> Payload {
        try JWTParser(token: token).payload(as: Payload.self)
    }

    /// Verifies and parses a given token, throwing an error if the signature is invalid.
    /// - Parameters:
    ///   - token: The string containing the encoded token.
    ///   - payload: The type to parse the payload as. Must conform to `JWTPayload`.
    public func verify<Payload: JWTPayload>(
        _ token: String,
        as payload: Payload.Type = Payload.self
    ) throws -> Payload {
        try self.verify([UInt8](token.utf8), as: Payload.self)
    }

    /// Verifies and parses a given token, throwing an error if the signature is invalid.
    /// - Parameters:
    ///   - token: The instance of `DataProtocol` containing the encoded token.
    ///   - payload: The type to parse the payload as. Must conform to `JWTPayload`.
    public func verify<Message: DataProtocol, Payload: JWTPayload>(
        _ token: Message,
        as payload: Payload.Type = Payload.self
    ) throws -> Payload {
        let parser = try JWTParser(token: token)
        return try self.verify(parser: parser)
    }

    /// Verifies and parses a given token using a pre-initialized `JWTParser`.
    /// - Parameters:
    ///   - parser: The `JWTParser` initialized with the token.
    func verify<Payload: JWTPayload>(parser: JWTParser) throws -> Payload {
        try parser.verify(using: self)
        let payload = try parser.payload(as: Payload.self)
        try payload.verify(using: self)
        return payload
    }
}
