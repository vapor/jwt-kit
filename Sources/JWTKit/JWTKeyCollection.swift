import Foundation

/// A collection of JWT and JWK signers for handling JSON Web Tokens (JWTs).
///
/// This actor provides methods to manage multiple keys. It can be used to verify and decode JWTs, as well as to sign and encode JWTs.
/// It also facilitates the encoding and decoding of JWTs using custom or default JSON encoders and decoders.
public actor JWTKeyCollection: Sendable {
    private enum Signer {
        case jwt(JWTSigner)
        case jwk(JWKSigner)
    }

    private var storage: [JWKIdentifier: Signer]
    private var `default`: Signer?

    /// The default JSON encoder. Used for:
    ///
    /// - Encoding the JSON form of a JWKS.
    /// - Encoding unverified payloads without a signer.
    public let defaultJSONEncoder: any JWTJSONEncoder

    /// The default JSON decoder. Used for:
    ///
    /// - Parsing the JSON form of a JWKS.
    /// - Decoding unverified payloads without a signer.
    /// - Decoding token headers to determine a key type.
    public let defaultJSONDecoder: any JWTJSONDecoder

    /// Creates a new empty Signers collection.
    /// - parameters:
    ///    - jsonEncoder: The default JSON encoder.
    ///    - jsonDecoder: The default JSON decoder.
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
    ///   - signer: The ``JWTSigner`` instance to add.
    ///   - kid: An optional ``JWKIdentifier`` to associate with the signer.
    /// - Returns: Self for chaining.
    @discardableResult
    func add(_ signer: JWTSigner, for kid: JWKIdentifier? = nil) -> Self {
        let signer = JWTSigner(algorithm: signer.algorithm, jsonEncoder: signer.jsonEncoder, jsonDecoder: signer.jsonDecoder)

        if let kid = kid {
            if self.storage[kid] != nil {
                print("Warning: Overwriting existing JWT signer for key identifier '\(kid)'.")
            }
            self.storage[kid] = .jwt(signer)
        } else {
            if self.default != nil {
                print("Warning: Overwriting existing default JWT signer.")
            }
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
    ///   - isDefault: An optional Boolean indicating whether this key should be the default key.
    /// - Throws: ``JWTError/invalidJWK`` if the JWK cannot be added due to missing key identifier.
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

    /// Retrieves a ``JWTSigner`` associated with the provided key identifier (KID) and algorithm (ALG), if available.
    ///
    /// - Parameters:
    ///   - kid: An optional ``JWKIdentifier``. If not provided, the default signer is returned.
    ///   - alg: An optional algorithm identifier.
    /// - Returns: A ``JWTSigner`` if one is found; otherwise, `nil`.
    func signer(for kid: JWKIdentifier? = nil, alg: String? = nil) throws -> JWTSigner {
        let signer: Signer
        if let kid = kid, let stored = self.storage[kid] {
            signer = stored
        } else if let d = self.default {
            signer = d
        } else {
            throw JWTError.generic(identifier: "Key", reason: "Either a default key or a key identifier must be provided.")
        }

        switch signer {
        case let .jwt(jwt):
            return jwt
        case let .jwk(jwk):
            if let signer = jwk.signer(for: alg.flatMap { JWK.Algorithm(rawValue: $0) }) {
                return signer
            } else {
                throw JWTError.generic(identifier: "Algorithm", reason: "Invalid algorithm or unable to create signer with provided algorithm.")
            }
        }
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
    ) async throws -> Payload
        where Payload: JWTPayload
    {
        try await self.verify([UInt8](token.utf8), as: Payload.self)
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
    ) async throws -> Payload
        where Payload: JWTPayload
    {
        let parser = try JWTParser(token: token)
        let header = try parser.header(jsonDecoder: self.defaultJSONDecoder)
        let signer = try self.signer(for: header.kid, alg: header.alg)
        return try await signer.verify(parser: parser)
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
        let signer = try self.signer(for: kid)
        return try signer.sign(payload, typ: typ, kid: kid)
    }
}
