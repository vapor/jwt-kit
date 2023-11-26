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
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If provided, it will be used to identify this key
    ///          in the JWT `kid` header field.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder`` used for encoding JWTs.
    ///          If `nil`, a default encoder is used.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder`` used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), enabling method chaining.
    @discardableResult
    func addRS256(
        key: some RSAKey,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(
            algorithm: RSASigner(key: key, algorithm: .sha256, name: "RS256", padding: .insecurePKCS1v1_5),
            jsonEncoder: jsonEncoder,
            jsonDecoder: jsonDecoder
        ),
        for: kid)
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
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If provided, it will be used to identify this key
    ///          in the JWT `kid` header field.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder`` used for encoding JWTs.
    ///          If `nil`, a default encoder is used.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder`` used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), enabling method chaining.
    @discardableResult
    func addRS384(
        key: some RSAKey,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(
            algorithm: RSASigner(key: key, algorithm: .sha384, name: "RS384", padding: .insecurePKCS1v1_5),
            jsonEncoder: jsonEncoder,
            jsonDecoder: jsonDecoder
        ),
        for: kid)
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
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If provided, it will be used to identify this key
    ///          in the JWT `kid` header field.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder`` used for encoding JWTs.
    ///          If `nil`, a default encoder is used.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder`` used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), enabling method chaining.
    @discardableResult
    func addRS512(
        key: some RSAKey,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(
            algorithm: RSASigner(key: key, algorithm: .sha512, name: "RS512", padding: .insecurePKCS1v1_5),
            jsonEncoder: jsonEncoder,
            jsonDecoder: jsonDecoder
        ),
        for: kid)
    }

    // MARK: PSS

    /// Adds a PS256 key to the collection.
    ///
    /// This method configures and adds a PS256 (RSA PSS Signature with SHA-256) key to the collection. PS256
    /// uses RSASSA-PSS with SHA-256 for the RSA signature, which is considered more secure than PKCS#1 v1.5
    /// padding used in RS256.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addPS256(key: myRSAKey)
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
    func addPS256(
        key: some RSAKey,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(
            algorithm: RSASigner(key: key, algorithm: .sha256, name: "PS256", padding: .PSS),
            jsonEncoder: jsonEncoder,
            jsonDecoder: jsonDecoder
        ),
        for: kid)
    }

    /// Adds a PS384 key to the collection.
    ///
    /// This method configures and adds a PS256 (RSA PSS Signature with SHA-384) key to the collection. PS384
    /// uses RSASSA-PSS with SHA-384 for the RSA signature, which is considered more secure than PKCS#1 v1.5
    /// padding used in RS384.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addPS384(key: myRSAKey)
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
    func addPS384(
        key: some RSAKey,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(
            algorithm: RSASigner(key: key, algorithm: .sha384, name: "PS384", padding: .PSS),
            jsonEncoder: jsonEncoder,
            jsonDecoder: jsonDecoder
        ),
        for: kid)
    }

    /// Adds a PS512 key to the collection.
    ///
    /// This method configures and adds a PS512 (RSA PSS Signature with SHA-512) key to the collection. PS512
    /// uses RSASSA-PSS with SHA-512 for the RSA signature, which is considered more secure than PKCS#1 v1.5
    /// padding used in RS512.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addPS512(key: myRSAKey)
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
    func addPS512(
        key: some RSAKey,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(
            algorithm: RSASigner(key: key, algorithm: .sha512, name: "PS512", padding: .PSS),
            jsonEncoder: jsonEncoder,
            jsonDecoder: jsonDecoder
        ),
        for: kid)
    }
}
