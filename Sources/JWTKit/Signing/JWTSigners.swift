import class Foundation.JSONEncoder
import class Foundation.JSONDecoder
import struct Foundation.Data

/// A collection of signers labeled by `kid`.
public final class JWTSigners {
    /// Internal storage.
    private var storage: [JWKIdentifier: JWTSigner]
    
    /// Internal storage for RSA keys for JWK with unknown algorithm.
    private var rsaKeysStorage: [JWKIdentifier: RSAKey]

    private var `default`: JWTSigner?

    /// Create a new `JWTSigners`.
    public init() {
        self.storage = [:]
        self.rsaKeysStorage = [:]
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
    
    /// Adds a new RSA keys connected with JWK.
    public func use(rsaKey: RSAKey, kid: JWKIdentifier)
    {
        self.rsaKeysStorage[kid] = rsaKey
    }

    /// Gets a signer for the supplied `kid` and `algorithm`, if one exists.
    public func get(kid: JWKIdentifier? = nil, algorithm: String? = nil) -> JWTSigner? {
        if let kid = kid {
            if let jwtSigner = self.storage[kid] {
                return jwtSigner
            }
            
            guard let rsaKey = self.rsaKeysStorage[kid] else {
                return nil
            }
            
            guard let algorithm = algorithm else {
                return nil
            }
            
            guard let alg = JWK.Algorithm(rawValue: algorithm) else {
                return nil
            }
            
            return .rsaKey(rsaKey, algorithm: alg)
        } else {
            return self.default
        }
    }

    public func require(kid: JWKIdentifier? = nil, algorithm: String? = nil) throws -> JWTSigner {
        guard let signer = self.get(kid: kid, algorithm: algorithm) else {
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
        
        return try self.require(kid: header.kid, algorithm: header.alg).verify(parser: parser)
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
