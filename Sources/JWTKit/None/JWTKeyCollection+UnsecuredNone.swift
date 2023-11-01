extension JWTKeyCollection {
    @discardableResult
    func addUnsecured(
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(algorithm: UnsecuredNoneSigner(), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder), for: kid)
    }
}
