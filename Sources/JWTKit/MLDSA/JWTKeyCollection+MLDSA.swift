extension JWTKeyCollection {
    /// Adds an MLDSA key to the collection using an ``MLDSAKey``.
    ///
    /// This method incorporates an MLDSA (Module-Lattice-Based Digital Signature Algorithm) signer into the
    /// collection. MLDSA is a post-quantum signature scheme, whose use in JWTs is defined by
    /// [RFC 9964](https://datatracker.ietf.org/doc/rfc9964/).
    ///
    /// Usage Example:
    /// ```
    /// let privateKey = try MLDSA87PrivateKey(seedRepresentation: seed)
    /// let collection = await JWTKeyCollection()
    ///     .add(mldsa: privateKey)
    /// ```
    ///
    /// - Parameters:
    ///   - key: The ``MLDSAKey`` used for MLDSA signing. Passing a private key allows both signing and
    ///          verifying, while passing a public key only allows verifying.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). Providing this identifier allows the JWT `kid` header field
    ///          to reference this specific signer.
    ///   - parser: An optional custom parser that conforms to ``JWTParser``. If not specified,
    ///          a ``DefaultJWTParser`` is used for parsing JWTs.
    ///   - serializer: An optional custom serializer that conforms to ``JWTSerializer``. If not specified,
    ///          a ``DefaultJWTSerializer`` is used for serializing JWTs.
    /// - Returns: The same instance of the collection (`Self`), useful for chaining multiple configuration calls.
    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
    @discardableResult
    public func add(
        mldsa key: some MLDSAKey,
        kid: JWKIdentifier? = nil,
        parser: some JWTParser = DefaultJWTParser(),
        serializer: some JWTSerializer = DefaultJWTSerializer()
    ) -> Self {
        self.add(
            .init(algorithm: MLDSASigner(key: key), parser: parser, serializer: serializer),
            for: kid
        )
    }
}
