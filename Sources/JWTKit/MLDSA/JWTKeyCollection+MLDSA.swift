extension JWTKeyCollection {
    @_spi(PostQuantum)
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
