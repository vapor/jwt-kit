import CryptoExtras

extension JWK {
    /// Builds the signing algorithm this key describes, or `nil` when the key is well formed but
    /// can't be used with the requested algorithm.
    func getKey(for alg: Algorithm? = nil) throws -> (any JWTAlgorithm)? {
        let algorithm = alg ?? self.algorithm

        switch self.keyType.backing {
        case .rsa:
            guard let modulus, let exponent else {
                throw JWTError.invalidJWK(reason: "Missing RSA primitives")
            }
            return try self.rsaSigner(modulus: modulus, exponent: exponent, algorithm: algorithm)
        case .ecdsa:
            guard let x, let y else {
                throw JWTError.invalidJWK(reason: "Missing ECDSA coordinates")
            }
            return try self.ecdsaSigner(x: x, y: y, algorithm: algorithm)
        case .octetKeyPair:
            guard case .eddsa(let curve) = self.curve?.backing else {
                throw JWTError.invalidJWK(reason: "Invalid EdDSA curve")
            }
            guard let x else {
                return nil
            }
            return try self.eddsaSigner(x: x, curve: curve, algorithm: algorithm)
        case .unknown:
            return nil
        }
    }

    private func rsaSigner(modulus: String, exponent: String, algorithm: Algorithm?) throws -> (any JWTAlgorithm)? {
        let key: any RSAKey =
            if let privateExponent {
                if let prime1, let prime2 {
                    try Insecure.RSA.PrivateKey(
                        modulus: modulus,
                        exponent: exponent,
                        privateExponent: privateExponent,
                        prime1: prime1,
                        prime2: prime2
                    )
                } else {
                    try Insecure.RSA.PrivateKey(
                        modulus: modulus,
                        exponent: exponent,
                        privateExponent: privateExponent
                    )
                }
            } else {
                try Insecure.RSA.PublicKey(modulus: modulus, exponent: exponent)
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

    private func ecdsaSigner(x: String, y: String, algorithm: Algorithm?) throws -> (any JWTAlgorithm)? {
        // If `crv` is present, it must match the key's curve
        let declaredCurve: ECDSACurve?
        switch self.curve?.backing {
        case .ecdsa(let curve):
            declaredCurve = curve
        case nil:
            declaredCurve = nil
        case .eddsa, .unknown:
            throw JWTError.invalidJWK(reason: "Invalid ECDSA curve")
        }

        func validateCurve(_ expected: ECDSACurve) throws {
            if let declaredCurve, declaredCurve != expected {
                throw JWTError.invalidJWK(reason: "Invalid ECDSA curve")
            }
        }

        switch algorithm?.backing {
        case .es256:
            try validateCurve(.p256)
            if let privateExponent {
                return try ECDSASigner(key: ES256PrivateKey(key: privateExponent))
            }
            return try ECDSASigner(key: ES256PublicKey(parameters: (x, y)))
        case .es384:
            try validateCurve(.p384)
            if let privateExponent {
                return try ECDSASigner(key: ES384PrivateKey(key: privateExponent))
            }
            return try ECDSASigner(key: ES384PublicKey(parameters: (x, y)))
        case .es512:
            try validateCurve(.p521)
            if let privateExponent {
                return try ECDSASigner(key: ES512PrivateKey(key: privateExponent))
            }
            return try ECDSASigner(key: ES512PublicKey(parameters: (x, y)))
        default:
            return nil
        }
    }

    private func eddsaSigner(x: String, curve: EdDSACurve, algorithm: Algorithm?) throws -> (any JWTAlgorithm)? {
        guard case .eddsa = algorithm?.backing else {
            return nil
        }

        if let privateExponent {
            return try EdDSASigner(key: EdDSA.PrivateKey(d: privateExponent, curve: curve))
        }
        return try EdDSASigner(key: EdDSA.PublicKey(x: x, curve: curve))
    }
}
