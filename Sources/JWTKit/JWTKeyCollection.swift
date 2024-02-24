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
    
    public let defaultJWTParser: any JWTParser
    public let defaultJWTSerializer: any JWTSerializer

    /// Creates a new empty Signers collection.
    /// - parameters:
    ///    - jsonEncoder: The default JSON encoder.
    ///    - jsonDecoder: The default JSON decoder.
    public init(defaultJWTParser: some JWTParser = DefaultJWTParser(), defaultJWTSerializer: some JWTSerializer = DefaultJWTSerializer()) {
        self.storage = [:]
        self.defaultJWTParser = defaultJWTParser
        self.defaultJWTSerializer = defaultJWTSerializer
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
        let signer = JWTSigner(algorithm: signer.algorithm, parser: signer.parser, serializer: signer.serializer)

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
        let jwks = try self.defaultJWTParser.jsonDecoder.decode(JWKS.self, from: Data(json.utf8))
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
        let signer = JWKSigner(jwk: jwk, parser: defaultJWTParser, serializer: defaultJWTSerializer)
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
    func getSigner(for kid: JWKIdentifier? = nil, alg: String? = nil) throws -> JWTSigner {
        let signer: Signer
        if let kid = kid, let stored = self.storage[kid] {
            signer = stored
        } else if let d = self.default {
            signer = d
        } else {
            throw JWTError.noKeyProvided
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

    /// Retrieves the key associated with the provided key identifier (KID) and algorithm (ALG), if available.
    /// - Parameters:
    ///  - kid: An optional ``JWKIdentifier``. If not provided, the default signer is returned.
    ///  - alg: An optional algorithm identifier.
    /// - Returns: A ``JWTKey`` if one is found; otherwise, `nil`.
    /// - Throws: ``JWTError/generic`` if the algorithm cannot be retrieved.
    public func getKey(for kid: JWKIdentifier? = nil, alg: String? = nil) throws -> JWTAlgorithm {
        try self.getSigner(for: kid, alg: alg).algorithm
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
        as _: Payload.Type = Payload.self,
        parser: (some JWTParser)? = nil
    ) throws -> Payload
        where Payload: JWTPayload
    {
        try self.unverified([UInt8](token.utf8), parser: parser)
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
        as _: Payload.Type = Payload.self,
        parser: (some JWTParser)? = nil
    ) throws -> Payload
        where Payload: JWTPayload
    {
        try (parser ?? defaultJWTParser).parse(token, as: Payload.self).payload
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
        _ token: some DataProtocol & Sendable,
        as _: Payload.Type = Payload.self
    ) async throws -> Payload
        where Payload: JWTPayload
    {
        let header = try defaultJWTParser.parseHeader(token)
        let kid = header.kid.flatMap { JWKIdentifier(string: $0) }
        let signer = try self.getSigner(for: kid, alg: header.alg)
        return try await signer.verify(token)
    }

    /// Signs a JWT payload and returns the JWT string.
    ///
    /// - Parameters:
    ///   - payload: The payload to sign.
    ///   - typ: The JWT type header parameter. Defaults to "JWT".
    ///   - kid: An optional key identifier to specify the signer. If not provided, the default signer is used.
    ///   - x5c: An optional certificate chain to include in the header.
    ///   - customFields: An optional dictionary of custom fields to include in the header.
    /// - Throws: An error if the payload cannot be signed.
    /// - Returns: A signed JWT token string.
    public func sign(
        _ payload: some JWTPayload,
        header: JWTHeader = JWTHeader()
    ) async throws -> String {
        let kid = header.kid.flatMap { JWKIdentifier(string: $0) }
        let signer = try self.getSigner(for: kid, alg: header.alg)
        return try await signer.sign(payload, with: header)
    }
}
