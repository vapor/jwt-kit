import Crypto
import Foundation

public extension JWTKeyCollection {
    // MARK: 256

    /// Adds an HS256 key to the collection.
    ///
    /// This method configures and adds an HS256 (HMAC with SHA-256) key to the collection.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addHS256(key: "mySecretKey")
    /// ```
    ///
    /// - Parameters:
    ///   - key: The secret key as a `String` used for HMAC signing. This key should be kept confidential
    ///          and secure, as it can be used for both signing and verification.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If given, it is used in the JWT `kid` header field
    ///          to identify this key.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder``, used for encoding JWTs.
    ///          If `nil`, a default encoder is employed.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder``, used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), enabling method chaining.
    @discardableResult
    func addHS256(
        key: String,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        addHS256(key: [UInt8](key.utf8), kid: kid, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    /// Adds an HS256 key to the collection.
    ///
    /// This method configures and adds an HS256 (HMAC with SHA-256) key to the collection.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addHS256(key: "mySecretKey")
    /// ```
    ///
    /// - Parameters:
    ///   - key: The secret key as data conforming to `DataProtocol` used for HMAC signing. This key should be kept confidential
    ///          and secure, as it can be used for both signing and verification.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If given, it is used in the JWT `kid` header field
    ///          to identify this key.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder``, used for encoding JWTs.
    ///          If `nil`, a default encoder is employed.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder``, used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), enabling method chaining.
    @discardableResult
    func addHS256(
        key: some DataProtocol,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        let symmetricKey = SymmetricKey(data: key.copyBytes())
        return addHS256(key: symmetricKey, kid: kid, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }
    
    /// Adds an HS256 key to the collection.
    ///
    /// This method configures and adds an HS256 (HMAC with SHA-256) key to the collection.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addHS256(key: "mySecretKey")
    /// ```
    ///
    /// - Parameters:
    ///   - key: The `SymmetricKey` used for HMAC signing. This key should be kept confidential
    ///          and secure, as it can be used for both signing and verification.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If given, it is used in the JWT `kid` header field
    ///          to identify this key.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder``, used for encoding JWTs.
    ///          If `nil`, a default encoder is employed.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder``, used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), enabling method chaining.
    @discardableResult
    func addHS256(
        key: SymmetricKey,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(algorithm: HMACSigner<SHA256>(key: key, name: "HS256"), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder), for: kid)
    }
}

public extension JWTKeyCollection {
    // MARK: 384

    /// Adds an HS384 key to the collection.
    ///
    /// This method configures and adds an HS384 (HMAC with SHA-384) key to the collection.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addHS384(key: "mySecretKey")
    /// ```
    ///
    /// - Parameters:
    ///   - key: The secret key as a `String` used for HMAC signing. This key should be kept confidential
    ///          and secure, as it can be used for both signing and verification.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If given, it is used in the JWT `kid` header field
    ///          to identify this key.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder``, used for encoding JWTs.
    ///          If `nil`, a default encoder is employed.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder``, used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), enabling method chaining.
    @discardableResult
    func addHS384(
        key: String,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        addHS384(key: [UInt8](key.utf8), kid: kid, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    /// Adds an HS384 key to the collection.
    ///
    /// This method configures and adds an HS384 (HMAC with SHA-384) key to the collection.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addHS384(key: "mySecretKey")
    /// ```
    ///
    /// - Parameters:
    ///   - key: The secret key as data conforming to `DataProtocol` used for HMAC signing. This key should be kept confidential
    ///          and secure, as it can be used for both signing and verification.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If given, it is used in the JWT `kid` header field
    ///          to identify this key.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder``, used for encoding JWTs.
    ///          If `nil`, a default encoder is employed.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder``, used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), enabling method chaining.
    @discardableResult
    func addHS384(
        key: some DataProtocol,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        let symmetricKey = SymmetricKey(data: key.copyBytes())
        return addHS384(key: symmetricKey, kid: kid, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    /// Adds an HS384 key to the collection.
    ///
    /// This method configures and adds an HS384 (HMAC with SHA-384) key to the collection.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addHS384(key: "mySecretKey")
    /// ```
    ///
    /// - Parameters:
    ///   - key: The `SymmetricKey` used for HMAC signing. This key should be kept confidential
    ///          and secure, as it can be used for both signing and verification.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If given, it is used in the JWT `kid` header field
    ///          to identify this key.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder``, used for encoding JWTs.
    ///          If `nil`, a default encoder is employed.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder``, used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), enabling method chaining.
    @discardableResult
    func addHS384(
        key: SymmetricKey,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(algorithm: HMACSigner<SHA384>(key: key, name: "HS384"), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder), for: kid)
    }
}

public extension JWTKeyCollection {
    // MARK: 512

    /// Adds an HS512 key to the collection.
    ///
    /// This method configures and adds an HS512 (HMAC with SHA-512) key to the collection.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addHS256(key: "mySecretKey")
    /// ```
    ///
    /// - Parameters:
    ///   - key: The secret key as a `String` used for HMAC signing. This key should be kept confidential
    ///          and secure, as it can be used for both signing and verification.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If given, it is used in the JWT `kid` header field
    ///          to identify this key.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder``, used for encoding JWTs.
    ///          If `nil`, a default encoder is employed.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder``, used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), enabling method chaining.
    @discardableResult
    func addHS512(
        key: String,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        addHS512(key: [UInt8](key.utf8), kid: kid, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    /// Adds an HS512 key to the collection.
    ///
    /// This method configures and adds an HS512 (HMAC with SHA-512) key to the collection.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addHS256(key: "mySecretKey")
    /// ```
    ///
    /// - Parameters:
    ///   - key: The secret key as data conforming to `DataProtocol` used for HMAC signing. This key should be kept confidential and secure, as it can be used for both signing and verification.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If given, it is used in the JWT `kid` header field
    ///          to identify this key.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder``, used for encoding JWTs.
    ///          If `nil`, a default encoder is employed.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder``, used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), enabling method chaining.
    @discardableResult
    func addHS512(
        key: some DataProtocol,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        let symmetricKey = SymmetricKey(data: key.copyBytes())
        return addHS512(key: symmetricKey, kid: kid, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    /// Adds an HS512 key to the collection.
    ///
    /// This method configures and adds an HS512 (HMAC with SHA-512) key to the collection.
    ///
    /// Example Usage:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addHS256(key: "mySecretKey")
    /// ```
    ///
    /// - Parameters:
    ///   - key: The `SymmetricKey` used for HMAC signing. This key should be kept confidential and secure, as it can be used for both signing and verification.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). If given, it is used in the JWT `kid` header field
    ///          to identify this key.
    ///   - jsonEncoder: An optional custom JSON encoder conforming to ``JWTJSONEncoder``, used for encoding JWTs.
    ///          If `nil`, a default encoder is employed.
    ///   - jsonDecoder: An optional custom JSON decoder conforming to ``JWTJSONDecoder``, used for decoding JWTs.
    ///          If `nil`, a default decoder is used.
    /// - Returns: The same instance of the collection (`Self`), enabling method chaining.
    @discardableResult
    func addHS512(
        key: SymmetricKey,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(algorithm: HMACSigner<SHA512>(key: key, name: "HS512"), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder), for: kid)
    }
}
