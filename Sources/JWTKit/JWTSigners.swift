import class Foundation.JSONEncoder
import class Foundation.JSONDecoder
import struct Foundation.Data

/// A collection of signers labeled by `kid`.
public final class JWTSigners {
    /// Internal storage.
    private var storage: [JWKIdentifier: JWTSigner]

    private var `default`: JWTSigner?

    /// Create a new `JWTSigners`.
    public init() {
        self.storage = [:]
    }

    /// Adds a new signer.
    public func use(
        _ signer: JWTSigner,
        kid: JWKIdentifier? = nil,
        isDefault: Bool? = nil
    ) {
        if let kid = kid {
            self.storage[kid] = signer
        }
        if self.default == nil && isDefault != false {
            self.default = signer
        }
    }

    /// Gets a signer for the supplied `kid`, if one exists.
    public func get(kid: JWKIdentifier? = nil) -> JWTSigner? {
        if let kid = kid {
            return self.storage[kid]
        } else {
            return self.default
        }
    }

    public func require(kid: JWKIdentifier? = nil) throws -> JWTSigner {
        guard let signer = self.get(kid: kid) else {
            if let kid = kid {
                throw JWTError.unknownKID(kid)
            } else {
                throw JWTError.missingKIDHeader
            }
        }
        return signer
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
        let header = try parser.header()
        try parser.verify(using: self.require(kid: header.kid))
        return try parser.payload(as: Payload.self)
    }

    public func sign<Payload>(
        _ payload: Payload,
        kid: JWKIdentifier? = nil
    ) throws -> String
        where Payload: JWTPayload
    {
        return try JWTSerializer().sign(
            payload,
            using: self.require(kid: kid),
            kid: kid
        )
    }
}
