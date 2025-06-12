extension JWTKeyCollection {
    @_spi(PostQuantum)
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
