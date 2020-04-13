import Foundation

extension JWTSigners {
    /// Adds a `JWKS` (JSON Web Key Set) to this signers collection
    /// by first decoding the JSON string.
    public func use(jwksJSON json: String, defaultAlgorithm: JWK.Algorithm? = nil) throws {
        let jwks = try JSONDecoder().decode(JWKS.self, from: Data(json.utf8))
        try self.use(jwks: jwks, defaultAlgorithm: defaultAlgorithm)
    }
    
    /// Adds a `JWKS` (JSON Web Key Set) to this signers collection.
    public func use(jwks: JWKS, defaultAlgorithm: JWK.Algorithm? = nil) throws {
        try jwks.keys.forEach { try self.use(jwk: $0, defaultAlgorithm: defaultAlgorithm) }
    }
    
    /// Adds a `JWK` (JSON Web Key) to this signers collection.
    public func use(jwk: JWK, defaultAlgorithm: JWK.Algorithm? = nil) throws {
        guard let kid = jwk.keyIdentifier else {
            throw JWTError.invalidJWK
        }
        try self.use(.jwk(jwk, defaultAlgorithm: defaultAlgorithm), kid: kid)
    }
}

extension JWTSigner {
    /// Creates a JWT sign from the supplied JWK json string.
    public static func jwk(json: String, defaultAlgorithm: JWK.Algorithm? = nil) throws -> JWTSigner {
        let jwk = try JSONDecoder().decode(JWK.self, from: Data(json.utf8))
        return try self.jwk(jwk, defaultAlgorithm: defaultAlgorithm)
    }
    
    /// Creates a JWT signer with the supplied JWK
    public static func jwk(_ key: JWK, defaultAlgorithm: JWK.Algorithm? = nil) throws -> JWTSigner {
        switch key.keyType {
        case .rsa:
            guard let modulus = key.modulus else {
                throw JWTError.invalidJWK
            }
            guard let exponent = key.exponent else {
                throw JWTError.invalidJWK
            }
            guard let algorithm = (key.algorithm ?? defaultAlgorithm) else {
                throw JWTError.invalidJWK
            }
            
            guard let rsaKey = RSAKey(
                modulus: modulus,
                exponent: exponent,
                privateExponent: key.privateExponent
            ) else {
                throw JWTError.invalidJWK
            }
            
            switch algorithm {
            case .rs256:
                return JWTSigner.rs256(key: rsaKey)
            case .rs384:
                return JWTSigner.rs384(key: rsaKey)
            case .rs512:
                return JWTSigner.rs512(key: rsaKey)
            }
        }
    }
}
