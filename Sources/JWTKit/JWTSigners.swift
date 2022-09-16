import class Foundation.JSONEncoder
import class Foundation.JSONDecoder
import struct Foundation.Data

/// A collection of signers labeled by `kid`.
public final class JWTSigners {
    /// Internal storage.
    private enum Signer {
        case jwt(JWTSigner)
        case jwk(JWKSigner)
    }
    private var storage: [JWKIdentifier: Signer]
    private var `default`: Signer?

    /// Create a new `JWTSigners`.
    public init() {
        self.storage = [:]
    }

    /// Adds a new signer.
    /// - Parameters:
    ///   - signer: The `JWTSigner` to add.
    ///   - kid: The key ID to use for the new signer (if any).
    ///   - isDefault: Whether to use this signer as the default.
    public func use(
        _ signer: JWTSigner,
        kid: JWKIdentifier? = nil,
        isDefault: Bool? = nil
    ) {
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
    public func use(jwksJSON json: String) throws {
        let jwks = try JSONDecoder().decode(JWKS.self, from: Data(json.utf8))
        try self.use(jwks: jwks)
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
        let signer = JWKSigner(jwk: jwk)
        self.storage[kid] = .jwk(signer)
        switch (self.default, isDefault) {
        case (.none, .none), (_, .some(true)):
            self.default = .jwk(signer)
        default: break
        }
    }

    /// Gets a signer for the supplied `kid`, if one exists.
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

    /// Gets a signer for the supplied `kid`, throwing a `JWTError` if one doesn't exist.
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
        let header = try parser.header()
        return try self.require(kid: header.kid, alg: header.alg).verify(parser: parser)
    }


    /// Signs a JWT with a given payload and appropriate header values.
    /// - Parameters:
    ///   - payload: The JWT's payload type. Must conform to `JWTPayload`.
    ///   - typ: The signature's content type. Defaults to "JWT".
    ///   - kid: The key ID for the token (if any). This is used to fetch the signer that will be used (as set up with `func use(_ signer: JWTSigner, kid: JWKIdentifier?, isDefault: )`
    ///   - zip: The compression type to use for the payload (if any).
    public func sign<Payload: JWTPayload>(
        _ payload: Payload,
        typ: String = "JWT",
        kid: JWKIdentifier? = nil,
        zip: CompressionType? = nil
    ) throws -> String {
        return try JWTSerializer().sign(
            payload,
            using: self.require(kid: kid),
            typ: typ,
            kid: kid,
            zip: zip
        )
    }
}

/// A type that takes a JWK and gives a signer from the value.
private struct JWKSigner {
    /// The JWK to generate a signer from.
    let jwk: JWK

    /// Set up a `JWKSigner` with a given `JWK`.
    init(jwk: JWK) {
        self.jwk = jwk
    }

    /// A signer generated from the JWK.
    /// - Parameters:
    ///   - algorithm: An optional `JWK.Algorithm` value. If provided, it overrides the
    ///   algorithm set in the JWK. If there's no provided algorithm in both the call and the JWK,
    ///   the function returns nil.
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
                return JWTSigner.rs256(key: rsaKey)
            case .rs384:
                return JWTSigner.rs384(key: rsaKey)
            case .rs512:
                return JWTSigner.rs512(key: rsaKey)
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
            
            if let jwkCurve = self.jwk.curve {
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
                return JWTSigner.es256(key: ecKey)
            case .es384:
                return JWTSigner.es384(key: ecKey)
            case .es512:
                return JWTSigner.es512(key: ecKey)
            default:
                return nil
            }
        }
    }
}

