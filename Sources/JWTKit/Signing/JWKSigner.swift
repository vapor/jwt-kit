import Foundation

struct JWKSigner {
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
            }
        }
    }
}
