extension JWTKeyCollection {
    // MARK: 256

    @discardableResult
    func addES256(
        key: ES256Key,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(algorithm: ECDSASigner(key: key, algorithm: .sha256, name: "ES256"), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder), for: kid)
    }

    // MARK: 384

    @discardableResult
    func addES384(
        key: ES384Key,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(algorithm: ECDSASigner(key: key, algorithm: .sha384, name: "ES384"), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder), for: kid)
    }

    // MARK: 512

    @discardableResult
    func addES521(
        key: ES521Key,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(algorithm: ECDSASigner(key: key, algorithm: .sha512, name: "ES512"), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder), for: kid)
    }
}
