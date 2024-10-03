actor JWKSigner: Sendable {
    let jwk: JWK
    let parser: any JWTParser
    let serializer: any JWTSerializer
    private(set) var signer: JWTSigner?

    init(
        jwk: JWK,
        parser: some JWTParser = DefaultJWTParser(),
        serializer: some JWTSerializer = DefaultJWTSerializer()
    ) throws {
        self.jwk = jwk
        if let algorithm = try jwk.getKey() {
            self.signer = .init(algorithm: algorithm, parser: parser, serializer: serializer)
        } else {
            self.signer = nil
        }
        self.parser = parser
        self.serializer = serializer
    }

    func makeSigner(for algorithm: JWK.Algorithm) throws -> JWTSigner {
        guard let key = try jwk.getKey(for: algorithm) else {
            throw JWTError.invalidJWK(reason: "Unable to create signer with given algorithm")
        }

        let signer = JWTSigner(algorithm: key, parser: parser, serializer: serializer)
        self.signer = signer
        return signer
    }
}

extension JWK {
    func getKey(for alg: JWK.Algorithm? = nil) throws -> (any JWTAlgorithm)? {
        switch self.keyType.backing {
        case .rsa:
            guard
                let modulus = self.modulus,
                let exponent = self.exponent
            else {
                throw JWTError.invalidJWK(reason: "Missing RSA primitives")
            }

            let rsaKey: RSAKey =
                if let privateExponent = self.privateExponent {
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

            let algorithm = alg ?? self.algorithm

            switch algorithm {
            case .rs256:
                return RSASigner(
                    key: rsaKey, algorithm: .sha256, name: "RS256", padding: .insecurePKCS1v1_5)
            case .rs384:
                return RSASigner(
                    key: rsaKey, algorithm: .sha384, name: "RS384", padding: .insecurePKCS1v1_5)
            case .rs512:
                return RSASigner(
                    key: rsaKey, algorithm: .sha512, name: "RS512", padding: .insecurePKCS1v1_5)
            case .ps256:
                return RSASigner(key: rsaKey, algorithm: .sha256, name: "PS256", padding: .PSS)
            case .ps384:
                return RSASigner(key: rsaKey, algorithm: .sha384, name: "PS384", padding: .PSS)
            case .ps512:
                return RSASigner(key: rsaKey, algorithm: .sha512, name: "PS512", padding: .PSS)
            default:
                return nil
            }

        // ECDSA

        case .ecdsa:
            guard
                let x = self.x,
                let y = self.y
            else {
                throw JWTError.invalidJWK(reason: "Missing ECDSA coordinates")
            }

            let algorithm = alg ?? self.algorithm

            switch algorithm {
            case .es256:
                if let privateExponent = self.privateExponent {
                    return try ECDSASigner(key: ES256PrivateKey(key: privateExponent))
                } else {
                    return try ECDSASigner(key: ES256PublicKey(parameters: (x, y)))
                }
            case .es384:
                if let privateExponent = self.privateExponent {
                    return try ECDSASigner(key: ES384PrivateKey(key: privateExponent))
                } else {
                    return try ECDSASigner(key: ES384PublicKey(parameters: (x, y)))
                }
            case .es512:
                if let privateExponent = self.privateExponent {
                    return try ECDSASigner(key: ES512PrivateKey(key: privateExponent))
                } else {
                    return try ECDSASigner(key: ES512PublicKey(parameters: (x, y)))
                }
            default:
                return nil
            }

        // EdDSA

        case .octetKeyPair:
            guard let curve = self.curve.flatMap({ EdDSACurve(rawValue: $0.rawValue) }) else {
                throw JWTError.invalidJWK(reason: "Invalid EdDSA curve")
            }

            let algorithm = alg ?? self.algorithm

            switch (algorithm, self.x, self.privateExponent) {
            case (.eddsa, .some(_), .some(let d)):
                let key = try EdDSA.PrivateKey(d: d, curve: curve)
                return EdDSASigner(key: key)

            case (.eddsa, .some(let x), .none):
                let key = try EdDSA.PublicKey(x: x, curve: curve)
                return EdDSASigner(key: key)

            default:
                return nil
            }
        }
    }
}
