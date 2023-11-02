import Crypto
import Foundation

public extension JWTKeyCollection {
    /// Adds an EdDSA key to the collection using an ``EdDSAKey``.
    ///
    /// This method incorporates an EdDSA (Edwards-curve Digital Signature Algorithm) signer into the collection.
    ///
    /// Usage Example:
    /// ```
    /// let collection = await JWTKeyCollection()
    ///     .addEdDSA(key: myEdDSAKey)
    /// ```
    ///
    /// - Parameters:
    ///   - key: The ``EdDSAKey`` used for EdDSA signing. EdDSA keys are known for their short signature and key sizes,
    ///          which contribute to their efficiency and speed.
    ///   - kid: An optional ``JWKIdentifier`` (Key ID). Providing this identifier allows the JWT `kid` header field
    ///          to reference this specific signer.
    ///   - jsonEncoder: An optional custom JSON encoder that conforms to ``JWTJSONEncoder``. If not specified,
    ///          a default encoder is used for encoding JWT payloads.
    ///   - jsonDecoder: An optional custom JSON decoder that conforms to ``JWTJSONDecoder``. If not specified,
    ///          a default decoder is used for decoding JWT payloads.
    /// - Returns: The same instance of the collection (`Self`), useful for chaining multiple configuration calls.
    @discardableResult
    func addEdDSA(
        key: EdDSAKey,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(algorithm: EdDSASigner(key: key), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder), for: kid)
    }
}
