import Crypto
import Foundation

public extension JWTKeyCollection {
    /// Adds an HMAC key to the collection.
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
    func add(
        hmac key: HMACKey,
        digestAlgorithm: DigestAlgorithm,
        kid: JWKIdentifier? = nil,
        parser: some JWTParser = DefaultJWTParser(),
        serializer: some JWTSerializer = DefaultJWTSerializer()
    ) -> Self {
        switch digestAlgorithm.backing {
        case .sha256:
            add(.init(algorithm: HMACSigner<SHA256>(key: key.key, name: "HS256"), parser: parser, serializer: serializer), for: kid)
        case .sha384:
            add(.init(algorithm: HMACSigner<SHA384>(key: key.key, name: "HS384"), parser: parser, serializer: serializer), for: kid)
        case .sha512:
            add(.init(algorithm: HMACSigner<SHA512>(key: key.key, name: "HS512"), parser: parser, serializer: serializer), for: kid)
        }
    }
}
