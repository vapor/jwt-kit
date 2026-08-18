extension JWK {
    /// Builds the signing algorithm this key describes, or `nil` when the key is well formed but
    /// can't be used with the requested algorithm.
    func getKey(for alg: Algorithm? = nil) throws -> (any JWTAlgorithm)? {
        let algorithm = alg ?? self.algorithm

        switch self.parameters {
        case .rsa(let rsa):
            return try Self.signer(for: rsa, algorithm: algorithm)
        case .ec(let ec):
            return try Self.signer(for: ec, algorithm: algorithm)
        case .okp(let okp):
            return try Self.signer(for: okp, algorithm: algorithm)
        case .loose(let members):
            switch members.keyType.backing {
            case .rsa:
                throw JWTError.invalidJWK(reason: "Missing RSA primitives")
            case .ecdsa:
                throw JWTError.invalidJWK(reason: "Missing ECDSA coordinates")
            case .octetKeyPair:
                guard case .eddsa = members.curve?.backing else {
                    throw JWTError.invalidJWK(reason: "Invalid EdDSA curve")
                }
                return nil
            case .unknown:
                return nil
            }
        }
    }

    private static func signer(for rsa: RSA, algorithm: Algorithm?) throws -> (any JWTAlgorithm)? {
        let key: RSAKey =
            if let privateExponent = rsa.privateExponent {
                if let prime1 = rsa.prime1, let prime2 = rsa.prime2 {
                    try Insecure.RSA.PrivateKey(
                        modulus: rsa.modulus,
                        exponent: rsa.exponent,
                        privateExponent: privateExponent,
                        prime1: prime1,
                        prime2: prime2
                    )
                } else {
                    try Insecure.RSA.PrivateKey(
                        modulus: rsa.modulus,
                        exponent: rsa.exponent,
                        privateExponent: privateExponent
                    )
                }
            } else {
                try Insecure.RSA.PublicKey(modulus: rsa.modulus, exponent: rsa.exponent)
            }

        return switch algorithm?.backing {
        case .rs256:
            RSASigner(key: key, algorithm: .sha256, name: "RS256", padding: .insecurePKCS1v1_5)
        case .rs384:
            RSASigner(key: key, algorithm: .sha384, name: "RS384", padding: .insecurePKCS1v1_5)
        case .rs512:
            RSASigner(key: key, algorithm: .sha512, name: "RS512", padding: .insecurePKCS1v1_5)
        case .ps256:
            RSASigner(key: key, algorithm: .sha256, name: "PS256", padding: .PSS)
        case .ps384:
            RSASigner(key: key, algorithm: .sha384, name: "PS384", padding: .PSS)
        case .ps512:
            RSASigner(key: key, algorithm: .sha512, name: "PS512", padding: .PSS)
        default:
            nil
        }
    }

    private static func signer(for ec: EC, algorithm: Algorithm?) throws -> (any JWTAlgorithm)? {
        switch algorithm?.backing {
        case .es256:
            if let privateKey = ec.privateKey {
                return try ECDSASigner(key: ES256PrivateKey(key: privateKey))
            }
            return try ECDSASigner(key: ES256PublicKey(parameters: (ec.x, ec.y)))
        case .es384:
            if let privateKey = ec.privateKey {
                return try ECDSASigner(key: ES384PrivateKey(key: privateKey))
            }
            return try ECDSASigner(key: ES384PublicKey(parameters: (ec.x, ec.y)))
        case .es512:
            if let privateKey = ec.privateKey {
                return try ECDSASigner(key: ES512PrivateKey(key: privateKey))
            }
            return try ECDSASigner(key: ES512PublicKey(parameters: (ec.x, ec.y)))
        default:
            return nil
        }
    }

    private static func signer(for okp: OKP, algorithm: Algorithm?) throws -> (any JWTAlgorithm)? {
        guard case .eddsa(let curve) = okp.curve?.backing else {
            throw JWTError.invalidJWK(reason: "Invalid EdDSA curve")
        }

        guard case .eddsa = algorithm?.backing else {
            return nil
        }

        if let privateKey = okp.privateKey {
            return try EdDSASigner(key: EdDSA.PrivateKey(d: privateKey, curve: curve))
        }
        return try EdDSASigner(key: EdDSA.PublicKey(x: okp.x, curve: curve))
    }
}
