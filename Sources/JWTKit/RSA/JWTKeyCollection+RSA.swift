import _CryptoExtras

public extension JWTKeyCollection {
    /// Adds an RS256 key to the collection.
    ///
    /// This method configures and adds an RS256 (RSA Signature with SHA-256) key to the collection.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addRS256(key: myRSAKey)
    /// ```
    ///
    /// - Parameters:
    ///   - key: The ``RSAKey`` to use for signing. This key should be kept secure and not exposed.
    ///   - padding: The padding scheme to use for RSA signing. Defaults to `.PSS`.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If provided, it will be used to identify this key
    ///          in the JWT `kid` header field.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder`` used for encoding JWTs.
    ///          If `nil`, a default encoder is used.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder`` used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), enabling method chaining.
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

    /// Adds an RS384 key to the collection.
    ///
    /// This method configures and adds an RS384 (RSA Signature with SHA-384) key to the collection.
    ///
    /// Example Usage:
    /// ```
    /// let collection = try await JWTKeyCollection()
    ///     .addRS384(key: myRSAKey)
    /// ```
    ///
    /// - Parameters:
    ///   - key: The ``RSAKey`` to use for signing. This key should be kept secure and not exposed.
    ///   - padding: The padding scheme to use for RSA signing. Defaults to `.PSS`.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If provided, it will be used to identify this key
    ///          in the JWT `kid` header field.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder`` used for encoding JWTs.
    ///          If `nil`, a default encoder is used.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder`` used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), enabling method chaining.
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

    /// Adds an RS512 key to the collection.
    ///
    /// This method configures and adds an RS512 (RSA Signature with SHA-512) key to the collection.
    ///
    /// Example Usage:
    /// ```
    /// let collection = try await JWTKeyCollection()
    ///     .addRS512(key: myRSAKey)
    /// ```
    ///
    /// - Parameters:
    ///   - key: The ``RSAKey`` to use for signing. This key should be kept secure and not exposed.
    ///   - padding: The padding scheme to use for RSA signing. Defaults to `.PSS`.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If provided, it will be used to identify this key
    ///          in the JWT `kid` header field.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder`` used for encoding JWTs.
    ///          If `nil`, a default encoder is used.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder`` used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), enabling method chaining.
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
