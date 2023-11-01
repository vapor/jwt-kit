import Foundation

/// A collection of JWT and JWK signers for handling JSON Web Tokens (JWTs).
///
/// This class provides methods to manage multiple signers, allowing the addition and retrieval of ``JWTSigner`` and ``JWKSigner`` instances.
/// It also facilitates the encoding and decoding of JWTs using custom or default JSON encoders and decoders.
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

    /// Adds a ``JWTSigner`` to the collection, optionally associating it with a specific key identifier (KID).
    ///
    /// If no KID is provided, and no default signer is set, this signer becomes the default.
    ///
    /// - Parameters:
    ///   - signer: The `JWTSigner` instance to add.
    ///   - kid: An optional `JWKIdentifier` to associate with the signer.
    /// - Returns: Self for chaining.
    @discardableResult
    func add(_ signer: JWTSigner, for kid: JWKIdentifier? = nil) -> Self {
        let signer = JWTSigner(algorithm: signer.algorithm, jsonEncoder: signer.jsonEncoder, jsonDecoder: signer.jsonDecoder)

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

    /// Adds a `JWKS` (JSON Web Key Set) to the collection by decoding a JSON string.
    ///
    /// - Parameter json: A JSON string representing a JWKS.
    /// - Throws: An error if the JSON string cannot be decoded into a `JWKS` instance.
    /// - Returns: Self for chaining.
    @discardableResult
    public func use(jwksJSON json: String) throws -> Self {
        let jwks = try self.defaultJSONDecoder.decode(JWKS.self, from: Data(json.utf8))
        return try self.add(jwks: jwks)
    }

    /// Adds a `JWKS` (JSON Web Key Set) directly to the collection.
    ///
    /// - Parameter jwks: A `JWKS` instance.
    /// - Throws: An error if the JWKS cannot be added.
    /// - Returns: Self for chaining.
    @discardableResult
    public func add(jwks: JWKS) throws -> Self {
        try jwks.keys.forEach { try self.add(jwk: $0) }
        return self
    }

    /// Adds a single `JWK` (JSON Web Key) to the collection.
    ///
    /// - Parameters:
    ///   - jwk: A `JWK` instance to be added.
    ///   - isDefault: An optional Boolean indicating whether this key should be the default signer.
    /// - Throws: An error if the JWK cannot be added, typically due to missing key identifier.
    /// - Returns: Self for chaining.
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

    /// Retrieves a `JWTSigner` associated with the provided key identifier (KID) and algorithm (ALG), if available.
    ///
    /// - Parameters:
    ///   - kid: An optional `JWKIdentifier`. If not provided, the default signer is returned.
    ///   - alg: An optional algorithm identifier.
    /// - Returns: A `JWTSigner` if one is found; otherwise, `nil`.
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

    /// Retrieves a `JWTSigner` for the provided key identifier (KID) and algorithm (ALG), or throws an error if not found.
    ///
    /// - Parameters:
    ///   - kid: An optional `JWKIdentifier`. If not provided, the default signer is returned.
    ///   - alg: An optional algorithm identifier.
    /// - Throws: `JWTError.unknownKID` if the KID is unknown or `JWTError.missingKIDHeader` if the KID is missing.
    /// - Returns: A `JWTSigner`.
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

    /// Decodes an unverified JWT payload.
    ///
    /// This method does not verify the signature of the JWT and should be used with caution.
    ///
    /// - Parameters:
    ///   - token: A JWT token string.
    /// - Throws: An error if the payload cannot be decoded.
    /// - Returns: The decoded payload of the specified type.
    public func unverified<Payload>(
        _ token: String,
        as _: Payload.Type = Payload.self
    ) throws -> Payload
        where Payload: JWTPayload
    {
        try self.unverified([UInt8](token.utf8))
    }

    /// Decodes an unverified JWT payload.
    ///
    /// This method does not verify the signature of the JWT and should be used with caution.
    ///
    /// - Parameters:
    ///   - token: A JWT token.
    /// - Throws: An error if the payload cannot be decoded.
    /// - Returns: The decoded payload of the specified type.
    public func unverified<Payload>(
        _ token: some DataProtocol,
        as _: Payload.Type = Payload.self
    ) throws -> Payload
        where Payload: JWTPayload
    {
        try JWTParser(token: token).payload(as: Payload.self, jsonDecoder: self.defaultJSONDecoder)
    }

    /// Verifies and decodes a JWT token to extract the payload.
    ///
    /// - Parameters:
    ///   - token: A JWT token string.
    /// - Throws: An error if the token cannot be verified or decoded.
    /// - Returns: The verified and decoded payload of the specified type.
    public func verify<Payload>(
        _ token: String,
        as _: Payload.Type = Payload.self
    ) throws -> Payload
        where Payload: JWTPayload
    {
        try self.verify([UInt8](token.utf8), as: Payload.self)
    }

    /// Verifies and decodes a JWT token to extract the payload.
    ///
    /// - Parameters:
    ///   - token: A JWT token.
    /// - Throws: An error if the token cannot be verified or decoded.
    /// - Returns: The verified and decoded payload of the specified type.
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

    /// Signs a JWT payload and returns the JWT string.
    ///
    /// - Parameters:
    ///   - payload: The payload to sign.
    ///   - typ: The JWT type header parameter. Defaults to "JWT".
    ///   - kid: An optional key identifier to specify the signer. If not provided, the default signer is used.
    /// - Throws: An error if the payload cannot be signed.
    /// - Returns: A signed JWT token string.
    public func sign(
        _ payload: some JWTPayload,
        typ: String = "JWT",
        kid: JWKIdentifier? = nil
    ) throws -> String {
        let signer = try self.require(kid: kid)
        return try signer.sign(payload, typ: typ, kid: kid)
    }
}
