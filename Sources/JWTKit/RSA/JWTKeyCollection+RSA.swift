import _CryptoExtras

extension JWTKeyCollection {
    @discardableResult
    func addRS256(
        key: RSAKey,
        padding: _RSA.Signing.Padding = .PSS,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(algorithm: RSASigner(key: key, algorithm: .sha256, name: "RS256", padding: padding), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder), for: kid)
    }

    @discardableResult
    func addRS384(
        key: RSAKey,
        padding: _RSA.Signing.Padding = .PSS,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(algorithm: RSASigner(key: key, algorithm: .sha384, name: "RS384", padding: padding), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder), for: kid)
    }

    @discardableResult
    func addRS512(
        key: RSAKey,
        padding: _RSA.Signing.Padding = .PSS,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(algorithm: RSASigner(key: key, algorithm: .sha512, name: "RS512", padding: padding), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder), for: kid)
    }
}
