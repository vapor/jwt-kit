import Foundation

extension RSAKey {
    /// Creates a RSA key for supplied JWK.
    public static func jwk(json: String) throws -> RSAKey {
        let jwk = try JSONDecoder().decode(JWK.self, from: Data(json.utf8))
        return try self.jwk(jwk)
    }
    
    /// Creates a RSA key for supplied JWK.
    public static func jwk(_ key: JWK) throws -> RSAKey {
        switch key.keyType {
        case .rsa:
            guard let modulus = key.modulus else {
                throw JWTError.invalidJWK
            }
            guard let exponent = key.exponent else {
                throw JWTError.invalidJWK
            }
            
            guard let rsaKey = RSAKey(
                modulus: modulus,
                exponent: exponent,
                privateExponent: key.privateExponent
            ) else {
                throw JWTError.invalidJWK
            }
            
            return rsaKey
        }
    }
}
