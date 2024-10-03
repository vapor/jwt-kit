import Crypto

extension JWTKeyCollection {
    /// Adds an ECDSA key to the collection.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addECDSA(key: myECDSAKey)
    /// ```
    ///
    /// - Parameters:
    ///   - key: The ``ECDSAKey`` to be used for signing. This key should be securely stored and not exposed.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If provided, this identifier will be used in the JWT `kid`
    ///          header field to identify the key.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder``, used for encoding JWTs.
    ///          If `nil`, a default encoder is used.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder``, used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), which allows for method chaining.
    @discardableResult
    public func add(
        ecdsa key: some ECDSAKey,
        kid: JWKIdentifier? = nil,
        parser: some JWTParser = DefaultJWTParser(),
        serializer: some JWTSerializer = DefaultJWTSerializer()
    ) -> Self {
        add(
            .init(
                algorithm: ECDSASigner(key: key),
                parser: parser,
                serializer: serializer
            ), for: kid
        )
    }
}
