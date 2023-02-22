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
        return try self.require(kid: header.kid, alg: header.alg).verify(parser: parser)
    }

    public func sign<Payload>(
        _ payload: Payload,
        typ: String = "JWT",
        kid: JWKIdentifier? = nil
    ) throws -> String
        where Payload: JWTPayload
    {
        return try JWTSerializer().sign(
            payload,
            using: self.require(kid: kid),
            typ: typ,
            kid: kid
        )
    }
}

private struct JWKSigner {
    let jwk: JWK

    init(jwk: JWK) {
        self.jwk = jwk
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
                return JWTSigner.es256(key: ecKey)
            case .es384:
                return JWTSigner.es384(key: ecKey)
            case .es512:
                return JWTSigner.es512(key: ecKey)
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
                return key.map(JWTSigner.eddsa(_:))
                
            case (.eddsa, .some(let x), .none):
                let key = try? EdDSAKey.public(x: x, curve: curve)
                return key.map(JWTSigner.eddsa(_:))
                
            default:
                return nil
            }
        }
    }
}

