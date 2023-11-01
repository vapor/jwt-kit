import Foundation

public actor JWTKeyCollection: Sendable {
    private enum Signer {
        case jwt(JWTSigner)
        case jwk(JWKSigner)
    }

    private var storage: [JWKIdentifier: Signer]
    private var `default`: Signer?

    /// The default JSON encoder. Used as:
    ///
    /// - The default for any ``JWTSigner`` which does not specify its own encoder.
    public let defaultJSONEncoder: any JWTJSONEncoder

    /// The default JSON decoder. Used for:
    ///
    /// - Parsing the JSON form of a JWKS (see ``JWTSigners/use(jwksJSON:)``.
    /// - Decoding unverified payloads without a signer (see ``JWTSigners/unverified(_:as:)-3qzpk``).
    /// - Decoding token headers to determine a key type (see ``JWTSigners/verify(_:as:)-6tee7``).
    /// - The default for any``JWTSigner`` which does not specify its own encoder.
    public let defaultJSONDecoder: any JWTJSONDecoder

    /// Creates a new empty Signers collection.
    /// - parameters:
    ///    - jsonEncoder: The default JSON encoder. Used as the default for any ``JWTSigner`` which does not specify its own encoder.
    ///    - jsonDecoder: The default JSON decoder. Used as the default for any ``JWTSigner`` which does not specify its own decoder.
    public init(jsonEncoder: (any JWTJSONEncoder)? = nil, jsonDecoder: (any JWTJSONDecoder)? = nil) {
        self.storage = [:]
        self.defaultJSONEncoder = jsonEncoder ?? .defaultForJWT
        self.defaultJSONDecoder = jsonDecoder ?? .defaultForJWT
    }

    /// Adds a `JWTSigner` to this signers collection.
    @discardableResult
    func add(_ signer: JWTSigner, for kid: JWKIdentifier? = nil) -> Self {
        signer.jsonEncoder = signer.jsonEncoder ?? self.defaultJSONEncoder
        signer.jsonDecoder = signer.jsonDecoder ?? self.defaultJSONDecoder

        if let kid = kid {
            self.storage[kid] = .jwt(signer)
        } else {
            self.default = .jwt(signer)
        }
        if self.default == nil {
            self.default = .jwt(signer)
        }
        return self
    }

    /// Adds a `JWKS` (JSON Web Key Set) to this signers collection
    /// by first decoding the JSON string.
    @discardableResult
    public func use(jwksJSON json: String) throws -> Self {
        let jwks = try self.defaultJSONDecoder.decode(JWKS.self, from: Data(json.utf8))
        return try self.add(jwks: jwks)
    }

    /// Adds a `JWKS` (JSON Web Key Set) to this signers collection.
    @discardableResult
    public func add(jwks: JWKS) throws -> Self {
        try jwks.keys.forEach { try self.add(jwk: $0) }
        return self
    }

    /// Adds a `JWK` (JSON Web Key) to this signers collection.
    @discardableResult
    public func add(
        jwk: JWK,
        isDefault: Bool? = nil
    ) throws -> Self {
        guard let kid = jwk.keyIdentifier else {
            throw JWTError.invalidJWK
        }
        let signer = JWKSigner(jwk: jwk, jsonEncoder: self.defaultJSONEncoder, jsonDecoder: self.defaultJSONDecoder)
        self.storage[kid] = .jwk(signer)
        switch (self.default, isDefault) {
        case (.none, .none), (_, .some(true)):
            self.default = .jwk(signer)
        default: break
        }
        return self
    }

    /// Returns the signer for the supplied `kid` (key identifier) or `nil` if none is found.
    func signer(for kid: JWKIdentifier? = nil, alg: String? = nil) -> JWTSigner? {
        let signer: Signer
        if let kid = kid, let stored = self.storage[kid] {
            signer = stored
        } else if let d = self.default {
            signer = d
        } else {
            return nil
        }
        switch signer {
        case let .jwt(jwt):
            return jwt
        case let .jwk(jwk):
            return jwk.signer(for: alg.flatMap { JWK.Algorithm(rawValue: $0) })
        }
    }

    /// Returns the signer for the supplied `kid` (key identifier) or throws an error if none is found.
    func require(kid: JWKIdentifier? = nil, alg: String? = nil) throws -> JWTSigner {
        guard let signer = self.signer(for: kid, alg: alg) else {
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
        as _: Payload.Type = Payload.self
    ) throws -> Payload
        where Payload: JWTPayload
    {
        try self.unverified([UInt8](token.utf8))
    }

    public func unverified<Payload>(
        _ token: some DataProtocol,
        as _: Payload.Type = Payload.self
    ) throws -> Payload
        where Payload: JWTPayload
    {
        try JWTParser(token: token).payload(as: Payload.self, jsonDecoder: self.defaultJSONDecoder)
    }

    public func verify<Payload>(
        _ token: String,
        as _: Payload.Type = Payload.self
    ) throws -> Payload
        where Payload: JWTPayload
    {
        try self.verify([UInt8](token.utf8), as: Payload.self)
    }

    public func verify<Payload>(
        _ token: some DataProtocol,
        as _: Payload.Type = Payload.self
    ) throws -> Payload
        where Payload: JWTPayload
    {
        let parser = try JWTParser(token: token)
        let header = try parser.header(jsonDecoder: self.defaultJSONDecoder)
        let signer = try self.require(kid: header.kid, alg: header.alg)
        return try signer.verify(parser: parser)
    }

    func verify<Payload>(parser: JWTParser) throws -> Payload
        where Payload: JWTPayload
    {
        let header = try parser.header(jsonDecoder: self.defaultJSONDecoder)
        guard let signer = self.signer(for: JWKIdentifier(string: header.alg ?? "")) else {
            throw JWTError.unknownKID(header.kid ?? "")
        }
        try parser.verify(using: signer.algorithm)
        let payload = try parser.payload(as: Payload.self, jsonDecoder: self.defaultJSONDecoder)
        try payload.verify(using: signer.algorithm)
        return payload
    }

    public func sign(
        _ payload: some JWTPayload,
        typ: String = "JWT",
        kid: JWKIdentifier? = nil
    ) throws -> String {
        let signer = try self.require(kid: kid)
        return try signer.sign(payload, typ: typ, kid: kid)
    }
}
