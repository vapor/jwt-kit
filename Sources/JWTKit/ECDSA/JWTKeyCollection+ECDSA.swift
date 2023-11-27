import Crypto

public extension JWTKeyCollection {
    /// Adds an ES256 key to the collection.
    ///
    /// This method configures and adds an ES256 (ECDSA using P-256 and SHA-256) key to the collection.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addES256(key: myES256Key)
    /// ```
    ///
    /// - Parameters:
    ///   - key: The ``ES256Key`` to be used for signing. This key should be securely stored and not exposed.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If provided, this identifier will be used in the JWT `kid`
    ///          header field to identify the key.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder``, used for encoding JWTs.
    ///          If `nil`, a default encoder is used.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder``, used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), which allows for method chaining.
    @discardableResult
    func addES256<Key: ECDSAKey>(
        key: Key,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self
        where Key.Curve == P256
    {
        add(.init(
            algorithm: ECDSASigner(key: key, algorithm: .sha256, name: "ES256"),
            jsonEncoder: jsonEncoder,
            jsonDecoder: jsonDecoder
        ), for: kid)
    }

    /// Adds an ES384 key to the collection.
    ///
    /// This method configures and adds an ES384(ECDSA using P-384 and SHA-384) key to the collection.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addES384(key: myES384Key)
    /// ```
    ///
    /// - Parameters:
    ///   - key: The ``ES384Key`` to be used for signing. This key should be securely stored and not exposed.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If provided, this identifier will be used in the JWT `kid`
    ///          header field to identify the key.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder``, used for encoding JWTs.
    ///          If `nil`, a default encoder is used.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder``, used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), which allows for method chaining.
    @discardableResult
    func addES384<Key: ECDSAKey>(
        key: Key,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self
        where Key.Curve == P384
    {
        add(.init(
            algorithm: ECDSASigner(key: key, algorithm: .sha384, name: "ES384"),
            jsonEncoder: jsonEncoder,
            jsonDecoder: jsonDecoder
        ), for: kid)
    }

    /// Adds an ES512 key to the collection.
    ///
    /// This method configures and adds an ES512 (ECDSA using P-521 and SHA-512) key to the collection.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addES512(key: myES512Key)
    /// ```
    ///
    /// - Parameters:
    ///   - key: The ``ES512Key`` to be used for signing. This key should be securely stored and not exposed.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If provided, this identifier will be used in the JWT `kid`
    ///          header field to identify the key.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder``, used for encoding JWTs.
    ///          If `nil`, a default encoder is used.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder``, used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), which allows for method chaining.
    @discardableResult
    func addES512<Key: ECDSAKey>(
        key: Key,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self
        where Key.Curve == P521
    {
        add(.init(
            algorithm: ECDSASigner(key: key, algorithm: .sha512, name: "ES512"),
            jsonEncoder: jsonEncoder,
            jsonDecoder: jsonDecoder
        ), for: kid)
    }
}
