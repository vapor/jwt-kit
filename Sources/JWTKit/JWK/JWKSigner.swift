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
                rsaKey = try RSAKey(modulus: modulus, exponent: exponent, privateExponent: self.jwk.privateExponent)
            } catch {
                return nil
            }

            guard let algorithm = algorithm ?? self.jwk.algorithm else {
                return nil
            }

            switch algorithm {
            case .rs256:
                return .init(algorithm: RSASigner(key: rsaKey, algorithm: .sha256, name: "RS256"))
            case .rs384:
                return .init(algorithm: RSASigner(key: rsaKey, algorithm: .sha384, name: "RS384"))
            case .rs512:
                return .init(algorithm: RSASigner(key: rsaKey, algorithm: .sha512, name: "RS512"))
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
                    return try .init(algorithm: ECDSASigner(
                        key: ES256Key(parameters: (x, y), privateKey: self.jwk.privateExponent),
                        algorithm: .sha256,
                        name: "ES256"
                    ))
                case .es384:
                    return try .init(algorithm: ECDSASigner(
                        key: ES384Key(parameters: (x, y), privateKey: self.jwk.privateExponent),
                        algorithm: .sha384,
                        name: "ES384"
                    ))
                case .es512:
                    return try .init(algorithm: ECDSASigner(
                        key: ES512Key(parameters: (x, y), privateKey: self.jwk.privateExponent),
                        algorithm: .sha512,
                        name: "ES512"
                    ))
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
