@_implementationOnly import CJWTKitBoringSSL
import class Foundation.JSONEncoder
import class Foundation.JSONDecoder

extension JWTSigner {
    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection.add(ecdsa:kid:) instead.")
    public static func es256(key: ECDSAKey) -> JWTSigner { .es256(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection.add(ecdsa:kid:) instead.")
    public static func es256(key: ECDSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: ECDSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha256(),
            name: "ES256"
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection.add(ecdsa:kid:) instead.")
    public static func es384(key: ECDSAKey) -> JWTSigner { .es384(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection.add(ecdsa:kid:) instead.")
    public static func es384(key: ECDSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: ECDSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha384(),
            name: "ES384"
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection.add(ecdsa:kid:) instead.")
    public static func es512(key: ECDSAKey) -> JWTSigner { .es512(key: key, jsonEncoder: nil, jsonDecoder: nil) }

    @available(*, deprecated, message: "Unavailable in v5. Please use JWTKeyCollection.add(ecdsa:kid:) instead.")
    public static func es512(key: ECDSAKey, jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: ECDSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha512(),
            name: "ES512"
        ), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }
}

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
    /// - Returns: The same instance of the collection (`Self`), which allows for method chaining.
    @discardableResult
    public func add<T>(
        ecdsa key: ECDSA.PublicKey<T>,
        kid: JWKIdentifier? = nil
    ) -> Self {
        switch key.curve {
        case .p256:
            try signers.use(.es256(key: key.key), kid: kid)
        case .p384:
            try signers.use(.es384(key: key.key), kid: kid)
        case .p521:
            try signers.use(.es512(key: key.key), kid: kid)
        case .ed25519, .ed448, .none:
            fatalError("Unsupported ECDSA key curve: \(key.curve?.rawValue ?? ".none")")
        }
        return self
    }

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
    /// - Returns: The same instance of the collection (`Self`), which allows for method chaining.
    @discardableResult
    public func add<T>(
        ecdsa key: ECDSA.PrivateKey<T>,
        kid: JWKIdentifier? = nil
    ) -> Self {
        switch key.curve {
        case .p256:
            try signers.use(.es256(key: key.key), kid: kid)
        case .p384:
            try signers.use(.es384(key: key.key), kid: kid)
        case .p521:
            try signers.use(.es512(key: key.key), kid: kid)
        case .ed25519, .ed448, .none:
            fatalError("Unsupported ECDSA key curve: \(key.curve?.rawValue ?? ".none")")
        }
        return self
    }
}
