import class Foundation.JSONEncoder
import class Foundation.JSONDecoder
import struct Foundation.Data
@_implementationOnly import CJWTKitBoringSSL

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
    
    public func verifyJWSWithX5C<Payload>(
        _ token: String,
        as payload: Payload.Type = Payload.self,
        rootCert: String
    ) throws -> Payload
        where Payload: JWTPayload
    {
        try self.verifyJWSWithX5C([UInt8](token.utf8), as: Payload.self, rootCert: [UInt8](rootCert.utf8))
    }
    
    func addBoundaryToCert(_ cert: String) -> String {
        """
        -----BEGIN CERTIFICATE-----
        \(cert)
        -----END CERTIFICATE-----
        """
    }
    
    public func verifyJWSWithX5C<Message, Payload>(
        _ token: Message,
        as payload: Payload.Type = Payload.self,
        rootCert: Message
    ) throws -> Payload
        where Message: DataProtocol, Payload: JWTPayload
    {
        let parser = try JWTParser(token: token)
        let header = try parser.header()
        guard let x5c = header.x5c else {
            throw JWTError.generic(identifier: "JWS", reason: "No x5c certificates provided")
        }
        
        // Verify the chain
        // The first cert is used to sign the JWS
        // Each subsequent cert should be used to certify the previous one
        // For the last cert we can find the signer for the KID
        // https://datatracker.ietf.org/doc/html/rfc7515#section-4.1.6
        for (index, certificate) in x5c.enumerated() {
            if index == 0 {
                continue
            }
            
            if index == x5c.count {
                let rootCertx509 = try ECDSAKey.load(pem: rootCert) { bio in
                    CJWTKitBoringSSL_PEM_read_bio_X509(bio, nil, nil, nil)
                }
                defer { CJWTKitBoringSSL_X509_free(rootCertx509) }
                
                let certToVerify = addBoundaryToCert(certificate)
                let certToVerifyX509 = try ECDSAKey.load(pem: [UInt8](certToVerify.utf8)) { bio in
                    CJWTKitBoringSSL_PEM_read_bio_X509(bio, nil, nil, nil)
                }
                defer { CJWTKitBoringSSL_X509_free(certToVerifyX509) }
                
                let rootPKey = CJWTKitBoringSSL_X509_get_pubkey(rootCertx509)
                defer { CJWTKitBoringSSL_EVP_PKEY_free(rootPKey) }
                
                guard CJWTKitBoringSSL_X509_verify(certToVerifyX509, rootPKey) == 1 else {
                    throw JWTError.generic(identifier: "JWS", reason: "Certificate verification failed")
                }
            } else {
                let certString = addBoundaryToCert(certificate)
                
                let x509 = try ECDSAKey.load(pem: [UInt8](certString.utf8)) { bio in
                    CJWTKitBoringSSL_PEM_read_bio_X509(bio, nil, nil, nil)
                }
                defer { CJWTKitBoringSSL_X509_free(x509) }
                
                let cert2String = addBoundaryToCert(x5c[index-1])
                let x5092 = try ECDSAKey.load(pem: [UInt8](cert2String.utf8)) { bio in
                    CJWTKitBoringSSL_PEM_read_bio_X509(bio, nil, nil, nil)
                }
                defer { CJWTKitBoringSSL_X509_free(x5092) }
                
                let pkey = CJWTKitBoringSSL_X509_get_pubkey(x509)
                defer { CJWTKitBoringSSL_EVP_PKEY_free(pkey) }
                
                guard CJWTKitBoringSSL_X509_verify(x5092, pkey) == 1 else {
                    throw JWTError.generic(identifier: "JWS", reason: "Certificate verification failed")
                }
            }
        }
        
        guard let signingCert = x5c.first else {
            throw JWTError.generic(identifier: "JWS", reason: "No x5c certificates provided")
        }
        let keyData = addBoundaryToCert(signingCert)
        let ecdsaKey = try ECDSAKey.certificate(pem: keyData)
        
        let signer = JWTSigner(algorithm: ECDSASigner(key: ecdsaKey, algorithm: CJWTKitBoringSSL_EVP_sha256(), name: "ES256"))
        return try signer.verify(parser: parser)
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

