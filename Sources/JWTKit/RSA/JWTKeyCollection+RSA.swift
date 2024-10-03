import _CryptoExtras

extension JWTKeyCollection {
    /// Adds an RSA key to the collection.
    ///
    /// This method configures and adds an RSA key to the collection. The key is used for signing JWTs
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///    .addRSA(key: myRSAKey)
    /// ```
    ///
    /// - Parameters:
    ///   - key: The ``RSAKey`` to use for signing. This key should be kept secure and not exposed.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If provided, it will be used to identify this key
    ///       in the JWT `kid` header field.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder`` used for encoding JWTs.
    ///       If `nil`, a default encoder is used.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder`` used for decoding JWTs.
    ///       If `nil`, a default decoder is used.
    ///   - Returns: The same instance of the collection (`Self`), enabling method chaining.
    @discardableResult
    public func add(
        rsa key: some RSAKey,
        digestAlgorithm: DigestAlgorithm,
        kid: JWKIdentifier? = nil,
        parser: some JWTParser = DefaultJWTParser(),
        serializer: some JWTSerializer = DefaultJWTSerializer()
    ) -> Self {
        let name =
            switch digestAlgorithm.backing {
            case .sha256:
                "RS256"
            case .sha384:
                "RS384"
            case .sha512:
                "RS512"
            }

        return add(
            .init(
                algorithm: RSASigner(
                    key: key, algorithm: digestAlgorithm, name: name, padding: .insecurePKCS1v1_5),
                parser: parser,
                serializer: serializer
            ),
            for: kid)
    }

    /// Adds a PSS key to the collection.
    ///
    /// This method configures and adds a PSS (RSA PSS Signature) key to the collection. PSS
    /// uses RSASSA-PSS for the RSA signature, which is considered more secure than PKCS#1 v1.5
    /// padding used in RSA.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addPSS(key: myRSAKey)
    /// ```
    ///
    /// - Parameters:
    ///   - key: The ``RSAKey`` to use for signing. This key should be kept secure and not exposed.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If provided, it will be used to identify this key
    ///          in the JWT `kid` header field.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder`` used for encoding JWTs.
    ///          If `nil`, a default encoder is used.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder`` used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), enabling method chaining.
    @discardableResult
    public func add(
        pss key: some RSAKey,
        digestAlgorithm: DigestAlgorithm,
        kid: JWKIdentifier? = nil,
        parser: some JWTParser = DefaultJWTParser(),
        serializer: some JWTSerializer = DefaultJWTSerializer()
    ) -> Self {
        let name =
            switch digestAlgorithm.backing {
            case .sha256:
                "PS256"
            case .sha384:
                "PS384"
            case .sha512:
                "PS512"
            }

        return add(
            .init(
                algorithm: RSASigner(
                    key: key, algorithm: digestAlgorithm, name: name, padding: .PSS),
                parser: parser,
                serializer: serializer
            ),
            for: kid)
    }
}
