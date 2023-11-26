struct JWKSigner: Sendable {
    let jwk: JWK
    let jsonEncoder: any JWTJSONEncoder
    let jsonDecoder: any JWTJSONDecoder

    init(jwk: JWK, jsonEncoder: any JWTJSONEncoder, jsonDecoder: any JWTJSONDecoder) {
        self.jwk = jwk
        self.jsonEncoder = jsonEncoder
        self.jsonDecoder = jsonDecoder
    }

    func signer(for algorithm: JWK.Algorithm? = nil) -> JWTSigner? {
        switch jwk.keyType.backing {
        case .rsa:
            guard
                let modulus = self.jwk.modulus,
                let exponent = self.jwk.exponent
            else {
                return nil
            }
            
            let rsaKey: RSAKey
            do {
                if let privateExponent = jwk.privateExponent {
                    rsaKey = try RSA.PrivateKey(modulus: modulus, exponent: exponent, privateExponent: privateExponent)
                } else {
                    rsaKey = try RSA.PublicKey(modulus: modulus, exponent: exponent)
                }
            } catch {
                return nil
            }

            guard let algorithm = algorithm ?? self.jwk.algorithm else {
                return nil
            }

            switch algorithm {
            case .rs256:
                return .init(algorithm: RSASigner(key: rsaKey, algorithm: .sha256, name: "RS256", padding: .insecurePKCS1v1_5))
            case .rs384:
                return .init(algorithm: RSASigner(key: rsaKey, algorithm: .sha384, name: "RS384", padding: .insecurePKCS1v1_5))
            case .rs512:
                return .init(algorithm: RSASigner(key: rsaKey, algorithm: .sha512, name: "RS512", padding: .insecurePKCS1v1_5))
            case .ps256:
                return .init(algorithm: RSASigner(key: rsaKey, algorithm: .sha256, name: "PS256", padding: .PSS))
            case .ps384:
                return .init(algorithm: RSASigner(key: rsaKey, algorithm: .sha384, name: "PS384", padding: .PSS))
            case .ps512:
                return .init(algorithm: RSASigner(key: rsaKey, algorithm: .sha512, name: "PS512", padding: .PSS))
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
            
            do {
                switch algorithm {
                case .es256:
                    if let privateExponent = self.jwk.privateExponent {
                        return try .init(algorithm: ECDSASigner(
                            key: ES256PrivateKey(parameters: (x, y), privateKey: privateExponent),
                            algorithm: .sha256,
                            name: "ES256"
                        ))
                    } else {
                        return try .init(algorithm: ECDSASigner(
                            key: ES256PublicKey(parameters: (x, y)),
                            algorithm: .sha256,
                            name: "ES256"
                        ))
                    }
                    
                case .es384:
                    if let privateExponent = self.jwk.privateExponent {
                        return try .init(algorithm: ECDSASigner(
                            key: ES384PrivateKey(parameters: (x, y), privateKey: privateExponent),
                            algorithm: .sha384,
                            name: "ES384"
                        ))
                    } else {
                        return try .init(algorithm: ECDSASigner(
                            key: ES384PublicKey(parameters: (x, y)),
                            algorithm: .sha384,
                            name: "ES384"
                        ))
                    }
                case .es512:
                    if let privateExponent = self.jwk.privateExponent {
                        return try .init(algorithm: ECDSASigner(
                            key: ES512PrivateKey(parameters: (x, y), privateKey: privateExponent),
                            algorithm: .sha512,
                            name: "ES512"
                        ))
                    } else {
                        return try .init(algorithm: ECDSASigner(
                            key: ES512PublicKey(parameters: (x, y)),
                            algorithm: .sha512,
                            name: "ES512"
                        ))
                    }
                default:
                    return nil
                }
            } catch {
                return nil
            }
        case .octetKeyPair:
            guard let algorithm = algorithm ?? self.jwk.algorithm else {
                return nil
            }

            guard let curve = self.jwk.curve.flatMap({ EdDSACurve(rawValue: $0.rawValue) }) else {
                return nil
            }

            switch (algorithm, self.jwk.x, self.jwk.privateExponent) {
            case let (.eddsa, .some(x), .some(d)):
                let key = try? EdDSAKey.private(x: x, d: d, curve: curve)
                return key.map { .init(algorithm: EdDSASigner(key: $0)) }

            case let (.eddsa, .some(x), .none):
                let key = try? EdDSAKey.public(x: x, curve: curve)
                return key.map { .init(algorithm: EdDSASigner(key: $0)) }

            default:
                return nil
            }
        }
    }
}
