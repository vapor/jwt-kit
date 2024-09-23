extension JWTKeyCollection {
    /// Adds a configuration for JWTs without a signature.
    ///
    /// This method configures JWT processing to accept tokens with the 'none' algorithm, indicating that the JWT
    /// is not secured by a signature. Use this with caution, as it means the token's integrity and authenticity
    /// are not verified through cryptographic means.
    ///
    /// Tokens without a signature ('none' algorithm) are typically used in trusted environments or for specific
    /// use cases where security is not a primary concern, such as testing environments.
    ///
    /// Usage Example:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addUnsecuredNone()
    /// ```
    ///
    /// - Parameters:
    ///   - kid: An optional `JWKIdentifier` (Key ID). If provided, it is used in the JWT `kid` header field to
    ///          identify this key. While the key is unsecured, the `kid` can still be useful for
    ///          consistent token structure or for routing purposes.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to `JWTJSONEncoder`. This encoder is used
    ///          for encoding JWTs. If not provided, a default encoder is used.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to `JWTJSONDecoder`. This decoder is used
    ///          for decoding JWTs. If not provided, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), facilitating method chaining.
    ///
    /// Note: As this configuration does not secure the JWT, ensure its use is appropriate for the security
    /// requirements of your system. It is not recommended for scenarios where data integrity and authentication
    /// are critical.
    @discardableResult
    public func addUnsecuredNone(
        kid: JWKIdentifier? = nil,
        parser: some JWTParser = DefaultJWTParser(),
        serializer: some JWTSerializer = DefaultJWTSerializer()
    ) -> Self {
        add(
            .init(algorithm: UnsecuredNoneSigner(), parser: parser, serializer: serializer),
            for: kid)
    }
}
