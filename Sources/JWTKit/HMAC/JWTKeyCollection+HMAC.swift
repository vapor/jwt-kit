import Crypto

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

extension JWTKeyCollection {
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
    public func add(
        hmac key: HMACKey,
        digestAlgorithm: DigestAlgorithm,
        kid: JWKIdentifier? = nil,
        parser: some JWTParser = DefaultJWTParser(),
        serializer: some JWTSerializer = DefaultJWTSerializer()
    ) -> Self {
        let signer: any JWTAlgorithm =
            switch digestAlgorithm.backing {
            case .sha256:
                HMACSigner<SHA256>(key: key.key)
            case .sha384:
                HMACSigner<SHA384>(key: key.key)
            case .sha512:
                HMACSigner<SHA512>(key: key.key)
            }
        return add(.init(algorithm: signer, parser: parser, serializer: serializer), for: kid)
    }
}
