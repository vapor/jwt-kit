import Foundation

/// A collection of signers labeled by `kid`.
@available(*, deprecated, renamed: "JWTKeyCollection", message: "Unavailable in v5. Please use JWTKeyCollection instead.")
public final class JWTSigners {
    /// Internal storage.
    private enum Signer {
        case jwt(JWTSigner)
        case jwk(JWKSigner)
    }
    
    private var storage: [JWKIdentifier: Signer]
    private var `default`: Signer?
    
    /// The default JSON encoder. Used as:
    ///
    /// - The default for any ``JWTSigner`` which does not specify its own encoder.
    @available(*, deprecated, message: "Unavailable in v5.")
    public let defaultJSONEncoder: any JWTJSONEncoder
    
    /// The default JSON decoder. Used for:
    ///
    /// - Parsing the JSON form of a JWKS (see ``JWTSigners/use(jwksJSON:)``.
    /// - Decoding unverified payloads without a signer (see ``JWTSigners/unverified(_:as:)-3qzpk``).
    /// - Decoding token headers to determine a key type (see ``JWTSigners/verify(_:as:)-6tee7``).
    /// - The default for any``JWTSigner`` which does not specify its own encoder.
    @available(*, deprecated, message: "Unavailable in v5.")
    public let defaultJSONDecoder: any JWTJSONDecoder

    /// Create a new ``JWTSigners``.
    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection() instead.")
    public init() {
        self.storage = [:]
        self.defaultJSONEncoder = .defaultForJWT
        self.defaultJSONDecoder = .defaultForJWT
    }
    
    /// Create a new ``JWTSigners`` with specific JSON coders.
    @available(*, deprecated, message: "Unavailable in v5.")
    public init(defaultJSONEncoder: any JWTJSONEncoder, defaultJSONDecoder: any JWTJSONDecoder) {
        self.storage = [:]
        self.defaultJSONEncoder = defaultJSONEncoder
        self.defaultJSONDecoder = defaultJSONDecoder
    }
    
    /// Adds a new signer.
    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection.add(...) instead.")
    public func use(
        _ signer: JWTSigner,
        kid: JWKIdentifier? = nil,
        isDefault: Bool? = nil
    ) {
        signer.jsonEncoder = signer.jsonEncoder ?? self.defaultJSONEncoder
        signer.jsonDecoder = signer.jsonDecoder ?? self.defaultJSONDecoder
        
        if let kid = kid {
            self.storage[kid] = .jwt(signer)
        }
        switch (self.default, isDefault) {
        case (.none, .none), (_, .some(true)):
            self.default = .jwt(signer)
        default: break
        }
    }

    /// Adds a `JWKS` (JSON Web Key Set) to this signers collection
    /// by first decoding the JSON string.
    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection.add(jwksJSON:) instead.")
    public func use(jwksJSON json: String) throws {
        let jwks = try self.defaultJSONDecoder.decode(JWKS.self, from: Data(json.utf8))
        try self.use(jwks: jwks)
    }

    /// Adds a `JWKS` (JSON Web Key Set) to this signers collection.
    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection.add(jwks:) instead.")
    public func use(jwks: JWKS) throws {
        try jwks.keys.forEach { try self.use(jwk: $0) }
    }

    /// Adds a `JWK` (JSON Web Key) to this signers collection.
    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection.add(jwk:isDefault:) instead.")
    public func use(
        jwk: JWK,
        isDefault: Bool? = nil
    ) throws {
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
    }

    /// Gets a signer for the supplied `kid`, if one exists.
    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection.getKey(for:alg:) instead.")
    public func get(kid: JWKIdentifier? = nil, alg: String? = nil) -> JWTSigner? {
        let signer: Signer
        if let kid = kid, let stored = self.storage[kid] {
            signer = stored
        } else if let d = self.default {
            signer = d
        } else {
            return nil
        }
        switch signer {
        case .jwt(let jwt):
            return jwt
        case .jwk(let jwk):
            return jwk.signer(for: alg.flatMap({ JWK.Algorithm.init(rawValue: $0) }))
        }
    }

    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection.getKey(for:alg:) instead.")
    public func require(kid: JWKIdentifier? = nil, alg: String? = nil) throws -> JWTSigner {
        guard let signer = self.get(kid: kid, alg: alg) else {
            if let kid = kid {
                throw JWTError.unknownKID(kid)
            } else {
                throw JWTError.missingKIDHeader
            }
        }
        return signer
    }

    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection.unverified(_:as:) instead.")
    public func unverified<Payload>(
        _ token: String,
        as payload: Payload.Type = Payload.self
    ) throws -> Payload
        where Payload: JWTPayload
    {
        try self.unverified([UInt8](token.utf8))
    }

    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection.unverified(_:as:) instead.")
    public func unverified<Message, Payload>(
        _ token: Message,
        as payload: Payload.Type = Payload.self
    ) throws -> Payload
        where Message: DataProtocol, Payload: JWTPayload
    {
        try JWTParser(token: token).payload(as: Payload.self, jsonDecoder: self.defaultJSONDecoder)
    }

    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection.verify(_:as:) instead.")
    public func verify<Payload>(
        _ token: String,
        as payload: Payload.Type = Payload.self
    ) throws -> Payload
        where Payload: JWTPayload
    {
        try self.verify([UInt8](token.utf8), as: Payload.self)
    }

    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection.verify(_:as:) instead.")
    public func verify<Message, Payload>(
        _ token: Message,
        as payload: Payload.Type = Payload.self
    ) throws -> Payload
        where Message: DataProtocol, Payload: JWTPayload
    {
        let parser = try JWTParser(token: token)
        let header = try parser.header(jsonDecoder: self.defaultJSONDecoder)
        let signer = try self.require(kid: header.kid, alg: header.alg)
        return try signer.verify(parser: parser)
    }

    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection.sign(_:kid:) instead.")
    public func sign<Payload>(
        _ payload: Payload,
        typ: String = "JWT",
        kid: JWKIdentifier? = nil
    ) throws -> String
        where Payload: JWTPayload
    {
        let signer = try self.require(kid: kid)
        
        return try signer.sign(payload, typ: typ, kid: kid)
    }
}

private struct JWKSigner {
    let jwk: JWK
    let jsonEncoder: any JWTJSONEncoder
    let jsonDecoder: any JWTJSONDecoder

    init(jwk: JWK, jsonEncoder: any JWTJSONEncoder, jsonDecoder: any JWTJSONDecoder) {
        self.jwk = jwk
        self.jsonEncoder = jsonEncoder
        self.jsonDecoder = jsonDecoder
    }

    func signer(for algorithm: JWK.Algorithm? = nil) -> JWTSigner? {
        switch self.jwk.keyType {
        case .rsa:
            guard let modulus = self.jwk.modulus else {
                return nil
            }
            guard let exponent = self.jwk.exponent else {
                return nil
            }

            guard let rsaKey = RSAKey(
                modulus: modulus,
                exponent: exponent,
                privateExponent: self.jwk.privateExponent
            ) else {
                return nil
            }

            guard let algorithm = algorithm ?? self.jwk.algorithm else {
                return nil
            }

            switch algorithm {
            case .rs256:
                return JWTSigner.rs256(key: rsaKey, jsonEncoder: self.jsonEncoder, jsonDecoder: self.jsonDecoder)
            case .rs384:
                return JWTSigner.rs384(key: rsaKey, jsonEncoder: self.jsonEncoder, jsonDecoder: self.jsonDecoder)
            case .rs512:
                return JWTSigner.rs512(key: rsaKey, jsonEncoder: self.jsonEncoder, jsonDecoder: self.jsonDecoder)
            default:
                return nil
            }
        
        case .ecdsa:
            guard let x = self.jwk.x else {
                return nil
            }
            guard let y = self.jwk.y else {
                return nil
            }
            
            guard let algorithm = algorithm ?? self.jwk.algorithm else {
                return nil
            }
            
            let curve: ECDSAKey.Curve
            
            if let jwkCurve = (self.jwk.curve.flatMap { ECDSAKey.Curve(rawValue: $0.rawValue) }) {
                curve = jwkCurve
            } else {
                switch algorithm {
                case .es256:
                    curve = .p256
                case .es384:
                    curve = .p384
                case .es512:
                    curve = .p521
                default:
                    return nil
                }
            }
            
            guard let ecKey = try? ECDSAKey(parameters: .init(x: x, y: y), curve: curve, privateKey: self.jwk.privateExponent) else {
                return nil
            }

            switch algorithm {
            case .es256:
                return JWTSigner.es256(key: ecKey, jsonEncoder: self.jsonEncoder, jsonDecoder: self.jsonDecoder)
            case .es384:
                return JWTSigner.es384(key: ecKey, jsonEncoder: self.jsonEncoder, jsonDecoder: self.jsonDecoder)
            case .es512:
                return JWTSigner.es512(key: ecKey, jsonEncoder: self.jsonEncoder, jsonDecoder: self.jsonDecoder)
            default:
                return nil
            }

        case .octetKeyPair:
            guard let algorithm = algorithm ?? self.jwk.algorithm else {
                return nil
            }
                
            guard let curve = self.jwk.curve.flatMap({ EdDSAKey.Curve(rawValue: $0.rawValue) }) else {
                return nil
            }
            
            switch (algorithm, self.jwk.x, jwk.privateExponent) {
            case (.eddsa, .some(let x), .some(let d)):
                let key = try? EdDSAKey.private(x: x, d: d, curve: curve)
                return key.map { .eddsa($0, jsonEncoder: self.jsonEncoder, jsonDecoder: self.jsonDecoder) }
                
            case (.eddsa, .some(let x), .none):
                let key = try? EdDSAKey.public(x: x, curve: curve)
                return key.map { .eddsa($0, jsonEncoder: self.jsonEncoder, jsonDecoder: self.jsonDecoder) }
                
            default:
                return nil
            }
        }
    }
}

/// JWTKeyCollection was introduced in v5 and replaces ``JWTSigners``.
///
/// - Note: Please migrate over to ``JWTKeyCollection`` before updating to v5, though if you plan on remaining on v4, ``JWTSigners`` can continue to be used.
public actor JWTKeyCollection {
    var signers = JWTSigners()

    /// Creates a new empty Signers collection.
    public init() {}

    /// Adds a `JWKS` (JSON Web Key Set) to the collection by decoding a JSON string.
    ///
    /// - Parameter json: A JSON string representing a JWKS.
    /// - Throws: An error if the JSON string cannot be decoded into a `JWKS` instance.
    /// - Returns: Self for chaining.
    @discardableResult
    public func add(jwksJSON json: String) throws -> Self {
        try signers.use(jwksJSON: json)
        return self
    }

    /// Adds a `JWKS` (JSON Web Key Set) directly to the collection.
    ///
    /// - Parameter jwks: A `JWKS` instance.
    /// - Throws: An error if the JWKS cannot be added.
    /// - Returns: Self for chaining.
    @discardableResult
    public func add(jwks: JWKS) throws -> Self {
        try signers.use(jwks: jwks)
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
    public func add(jwk: JWK, isDefault: Bool? = nil) throws -> Self {
        try signers.use(jwk: jwk, isDefault: isDefault)
        return self
    }

    /// Retrieves the key associated with the provided key identifier (KID) and algorithm (ALG), if available.
    /// - Parameters:
    ///  - kid: An optional ``JWKIdentifier``. If not provided, the default signer is returned.
    ///  - alg: An optional algorithm identifier.
    /// - Returns: A ``JWTKey`` if one is found; otherwise, `nil`.
    /// - Throws: ``JWTError/generic`` if the algorithm cannot be retrieved.
    public func getKey(for kid: JWKIdentifier? = nil, alg: String? = nil) async throws -> any JWTAlgorithm {
        try signers.require(kid: kid, alg: alg).algorithm
    }

    /// Decodes an unverified JWT payload.
    ///
    /// This method does not verify the signature of the JWT and should be used with caution.
    ///
    /// - Parameters:
    ///   - token: A JWT token string.
    /// - Throws: An error if the payload cannot be decoded.
    /// - Returns: The decoded payload of the specified type.
    @available(*, deprecated, message: "Please make sure Payload conforms to AsyncJWTPayload instead of JWTPayload before updating to v5.")
    public func unverified<Payload>(
        _ token: String,
        as _: Payload.Type = Payload.self
    ) throws -> Payload
    where Payload: JWTPayload {
        try unverified(Array(token.utf8), as: Payload.self)
    }

    /// Decodes an unverified JWT payload.
    ///
    /// This method does not verify the signature of the JWT and should be used with caution.
    ///
    /// - Parameters:
    ///   - token: A JWT token.
    /// - Throws: An error if the payload cannot be decoded.
    /// - Returns: The decoded payload of the specified type.
    @available(*, deprecated, message: "Please make sure Payload conforms to AsyncJWTPayload instead of JWTPayload before updating to v5.")
    public func unverified<Payload, Data: DataProtocol>(
        _ token: Data,
        as _: Payload.Type = Payload.self
    ) throws -> Payload
    where Payload: JWTPayload {
        try JWTParser(token: token).payload(as: Payload.self, jsonDecoder: signers.defaultJSONDecoder)
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
    where Payload: AsyncJWTPayload {
        try unverified(Array(token.utf8), as: Payload.self)
    }

    /// Decodes an unverified JWT payload.
    ///
    /// This method does not verify the signature of the JWT and should be used with caution.
    ///
    /// - Parameters:
    ///   - token: A JWT token.
    /// - Throws: An error if the payload cannot be decoded.
    /// - Returns: The decoded payload of the specified type.
    public func unverified<Payload, Data: DataProtocol>(
        _ token: Data,
        as _: Payload.Type = Payload.self
    ) throws -> Payload
    where Payload: AsyncJWTPayload {
        try JWTParser(token: token).payload(as: Payload.self, jsonDecoder: signers.defaultJSONDecoder)
    }

    /// Verifies and decodes a JWT token to extract the payload.
    ///
    /// - Parameters:
    ///   - token: A JWT token string.
    ///   - as: The type of payload to decode.
    ///   - iteratingKeys: Whether to try verifying the token with all keys in the collection.
    /// - Throws: An error if the token cannot be verified or decoded.
    /// - Returns: The verified and decoded payload of the specified type.
    @available(*, deprecated, message: "Please make sure Payload conforms to AsyncJWTPayload instead of JWTPayload before updating to v5.")
    public func verify<Payload>(
        _ token: String,
        as _: Payload.Type = Payload.self,
        iteratingKeys: Bool = false
    ) async throws -> Payload
    where Payload: JWTPayload {
        try signers.verify(token, as: Payload.self)
    }

    /// Verifies and decodes a JWT token to extract the payload.
    ///
    /// - Parameters:
    ///   - token: A JWT token.
    ///   - as: The type of payload to decode.
    ///   - iteratingKeys: Whether to try verifying the token with all keys in the collection.
    /// - Throws: An error if the token cannot be verified or decoded.
    /// - Returns: The verified and decoded payload of the specified type.
    @available(*, deprecated, message: "Please make sure Payload conforms to AsyncJWTPayload instead of JWTPayload before updating to v5.")
    public func verify<Payload, Data: DataProtocol>(
        _ token: Data,
        as _: Payload.Type = Payload.self
    ) async throws -> Payload
    where Payload: JWTPayload {
        try signers.verify(token, as: Payload.self)
    }

    /// Verifies and decodes a JWT token to extract the payload.
    ///
    /// - Parameters:
    ///   - token: A JWT token string.
    ///   - as: The type of payload to decode.
    ///   - iteratingKeys: Whether to try verifying the token with all keys in the collection.
    /// - Throws: An error if the token cannot be verified or decoded.
    /// - Returns: The verified and decoded payload of the specified type.
    public func verify<Payload>(
        _ token: String,
        as _: Payload.Type = Payload.self,
        iteratingKeys: Bool = false
    ) async throws -> Payload
    where Payload: AsyncJWTPayload {
        try await verify(Array(token.utf8), as: Payload.self)
    }

    /// Verifies and decodes a JWT token to extract the payload.
    ///
    /// - Parameters:
    ///   - token: A JWT token.
    ///   - as: The type of payload to decode.
    ///   - iteratingKeys: Whether to try verifying the token with all keys in the collection.
    /// - Throws: An error if the token cannot be verified or decoded.
    /// - Returns: The verified and decoded payload of the specified type.
    public func verify<Payload, Data: DataProtocol>(
        _ token: Data,
        as _: Payload.Type = Payload.self
    ) async throws -> Payload
    where Payload: AsyncJWTPayload {
        let parser = try JWTParser(token: token)
        let header = try parser.header(jsonDecoder: signers.defaultJSONDecoder)
        let signer = try signers.require(kid: header.kid, alg: header.alg)
        return try await signer.verify(parser: parser)
    }
    
    /// Signs a JWT payload and returns the JWT string.
    ///
    /// - Parameters:
    ///   - payload: The payload to sign.
    ///   - kid: An optional key identifier to specify the signer.
    ///         If not provided, the header is checked for a KID,
    ///         and if that is not provided, the default signer is used.
    ///   - header: An optional header to include in the JWT.
    /// - Throws: An error if the payload cannot be signed.
    /// - Returns: A signed JWT token string.
    @available(*, deprecated, message: "Please make sure Payload conforms to AsyncJWTPayload instead of JWTPayload before updating to v5.")
    public func sign<Payload: JWTPayload>(
        _ payload: Payload,
        kid: JWKIdentifier? = nil
    ) async throws -> String {
        try signers.sign(payload, kid: kid)
    }
    
    /// Signs a JWT payload and returns the JWT string.
    ///
    /// - Parameters:
    ///   - payload: The payload to sign.
    ///   - kid: An optional key identifier to specify the signer.
    ///         If not provided, the header is checked for a KID,
    ///         and if that is not provided, the default signer is used.
    ///   - header: An optional header to include in the JWT.
    /// - Throws: An error if the payload cannot be signed.
    /// - Returns: A signed JWT token string.
    public func sign<Payload: AsyncJWTPayload>(
        _ payload: Payload,
        kid: JWKIdentifier? = nil
    ) async throws -> String {
        let signer = try signers.require(kid: kid)
        return try signer.sign(payload, kid: kid)
    }
}
