import Foundation

/// A collection of signers labeled by `kid`.
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
    public let defaultJSONEncoder: any JWTJSONEncoder

    /// The default JSON decoder. Used for:
    ///
    /// - Parsing the JSON form of a JWKS (see ``JWTSigners/use(jwksJSON:)``.
    /// - Decoding unverified payloads without a signer (see ``JWTSigners/unverified(_:as:)-3qzpk``).
    /// - Decoding token headers to determine a key type (see ``JWTSigners/verify(_:as:)-6tee7``).
    /// - The default for any``JWTSigner`` which does not specify its own encoder.
    public let defaultJSONDecoder: any JWTJSONDecoder

    /// Create a new ``JWTSigners``.
    public init() {
        storage = [:]
        defaultJSONEncoder = .defaultForJWT
        defaultJSONDecoder = .defaultForJWT
    }

    /// Create a new ``JWTSigners`` with specific JSON coders.
    public init(defaultJSONEncoder: any JWTJSONEncoder, defaultJSONDecoder: any JWTJSONDecoder) {
        storage = [:]
        self.defaultJSONEncoder = defaultJSONEncoder
        self.defaultJSONDecoder = defaultJSONDecoder
    }

    /// Adds a new signer.
    public func use(
        _ signer: JWTSigner,
        kid: JWKIdentifier? = nil,
        isDefault: Bool? = nil
    ) {
        signer.jsonEncoder = signer.jsonEncoder ?? defaultJSONEncoder
        signer.jsonDecoder = signer.jsonDecoder ?? defaultJSONDecoder

        if let kid = kid {
            storage[kid] = .jwt(signer)
        }
        switch (self.default, isDefault) {
        case (.none, .none), (_, .some(true)):
            self.default = .jwt(signer)
        default: break
        }
    }

    /// Adds a `JWKS` (JSON Web Key Set) to this signers collection
    /// by first decoding the JSON string.
    public func use(jwksJSON json: String) throws {
        let jwks = try defaultJSONDecoder.decode(JWKS.self, from: Data(json.utf8))
        try use(jwks: jwks)
    }

    /// Adds a `JWKS` (JSON Web Key Set) to this signers collection.
    public func use(jwks: JWKS) throws {
        try jwks.keys.forEach { try self.use(jwk: $0) }
    }

    /// Adds a `JWK` (JSON Web Key) to this signers collection.
    public func use(
        jwk: JWK,
        isDefault: Bool? = nil
    ) throws {
        guard let kid = jwk.keyIdentifier else {
            throw JWTError.invalidJWK
        }
        let signer = JWKSigner(jwk: jwk, jsonEncoder: defaultJSONEncoder, jsonDecoder: defaultJSONDecoder)
        storage[kid] = .jwk(signer)
        switch (self.default, isDefault) {
        case (.none, .none), (_, .some(true)):
            self.default = .jwk(signer)
        default: break
        }
    }

    /// Gets a signer for the supplied `kid`, if one exists.
    public func get(kid: JWKIdentifier? = nil, alg: String? = nil) -> JWTSigner? {
        let signer: Signer
        if let kid = kid, let stored = storage[kid] {
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

    public func require(kid: JWKIdentifier? = nil, alg: String? = nil) throws -> JWTSigner {
        guard let signer = get(kid: kid, alg: alg) else {
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
        try unverified([UInt8](token.utf8))
    }

    public func unverified<Message, Payload>(
        _ token: Message,
        as _: Payload.Type = Payload.self
    ) throws -> Payload
        where Message: DataProtocol, Payload: JWTPayload
    {
        try JWTParser(token: token).payload(as: Payload.self, jsonDecoder: defaultJSONDecoder)
    }

    public func verify<Payload>(
        _ token: String,
        as _: Payload.Type = Payload.self
    ) throws -> Payload
        where Payload: JWTPayload
    {
        try verify([UInt8](token.utf8), as: Payload.self)
    }

    public func verify<Message, Payload>(
        _ token: Message,
        as _: Payload.Type = Payload.self
    ) throws -> Payload
        where Message: DataProtocol, Payload: JWTPayload
    {
        let parser = try JWTParser(token: token)
        let header = try parser.header(jsonDecoder: defaultJSONDecoder)
        let signer = try require(kid: header.kid, alg: header.alg)
        return try signer.verify(parser: parser)
    }

    public func sign<Payload>(
        _ payload: Payload,
        typ: String = "JWT",
        kid: JWKIdentifier? = nil
    ) throws -> String
        where Payload: JWTPayload
    {
        let signer = try require(kid: kid)

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
        switch jwk.keyType {
        case .rsa:
            guard
                let modulus = jwk.modulus,
                let exponent = jwk.exponent
            else {
                return nil
            }

            let rsaKey: RSAKey

            do {
                rsaKey = try RSAKey(modulus: modulus, exponent: exponent, privateExponent: jwk.privateExponent)
            } catch {
                return nil
            }

            guard let algorithm = algorithm ?? jwk.algorithm else {
                return nil
            }

            switch algorithm {
            case .rs256:
                return JWTSigner.rs256(key: rsaKey, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
            case .rs384:
                return JWTSigner.rs384(key: rsaKey, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
            case .rs512:
                return JWTSigner.rs512(key: rsaKey, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
            default:
                return nil
            }

        case .ecdsa:
            guard let x = jwk.x else {
                return nil
            }
            guard let y = jwk.y else {
                return nil
            }

            guard let algorithm = algorithm ?? jwk.algorithm else {
                return nil
            }
            do {
                switch algorithm {
                case .es256:
                    return try JWTSigner.es256(
                        key: P256Key(parameters: .init(x: x, y: y), privateKey: jwk.privateExponent),
                        jsonEncoder: jsonEncoder,
                        jsonDecoder: jsonDecoder
                    )
                case .es384:
                    return try JWTSigner.es384(
                        key: P384Key(parameters: .init(x: x, y: y), privateKey: jwk.privateExponent),
                        jsonEncoder: jsonEncoder,
                        jsonDecoder: jsonDecoder
                    )
                case .es512:
                    return try JWTSigner.es512(
                        key: P521Key(parameters: .init(x: x, y: y), privateKey: jwk.privateExponent),
                        jsonEncoder: jsonEncoder,
                        jsonDecoder: jsonDecoder
                    )
                default:
                    return nil
                }
            } catch {
                return nil
            }
        case .octetKeyPair:
            guard let algorithm = algorithm ?? jwk.algorithm else {
                return nil
            }

            guard let curve = jwk.curve.flatMap({ EdDSAKey.Curve(rawValue: $0.rawValue) }) else {
                return nil
            }

            switch (algorithm, jwk.x, jwk.privateExponent) {
            case let (.eddsa, .some(x), .some(d)):
                let key = try? EdDSAKey.private(x: x, d: d, curve: curve)
                return key.map { .eddsa($0, jsonEncoder: self.jsonEncoder, jsonDecoder: self.jsonDecoder) }

            case let (.eddsa, .some(x), .none):
                let key = try? EdDSAKey.public(x: x, curve: curve)
                return key.map { .eddsa($0, jsonEncoder: self.jsonEncoder, jsonDecoder: self.jsonDecoder) }

            default:
                return nil
            }
        }
    }
}
