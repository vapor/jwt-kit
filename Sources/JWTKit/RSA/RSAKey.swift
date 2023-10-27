import _CryptoExtras
import Crypto
import Foundation
import SwiftASN1
import X509

public final class RSAKey {
    /// Creates RSAKey from public key pem file.
    ///
    /// Public key pem files look like:
    ///
    ///     -----BEGIN PUBLIC KEY-----
    ///     MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
    ///     ...
    ///     aX4rbSL49Z3dAQn8vQIDAQAB
    ///     -----END PUBLIC KEY-----
    ///
    /// This key can only be used to verify JWTs.
    ///
    /// - parameters:
    ///     - pem: Contents of pem file.
    public static func `public`(pem string: String) throws -> RSAKey {
        do {
            return try RSAKey(publicKey: .init(pemRepresentation: string))
        } catch CryptoKitError.incorrectParameterSize {
            throw RSAError.keySizeTooSmall
        }
    }

    /// Creates RSAKey from public key pem file.
    ///
    /// Public key pem files look like:
    ///
    ///     -----BEGIN PUBLIC KEY-----
    ///     MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
    ///     ...
    ///     aX4rbSL49Z3dAQn8vQIDAQAB
    ///     -----END PUBLIC KEY-----
    ///
    /// This key can only be used to verify JWTs.
    ///
    /// - parameters:
    ///     - pem: Contents of pem file.
    public static func `public`(pem data: some DataProtocol) throws -> RSAKey {
        let string = String(decoding: data, as: UTF8.self)
        return try self.public(pem: string)
    }

    /// Creates RSAKey from public certificate pem file.
    ///
    /// Certificate pem files look like:
    ///
    ///     -----BEGIN CERTIFICATE-----
    ///     MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
    ///     ...
    ///     aX4rbSL49Z3dAQn8vQIDAQAB
    ///     -----END CERTIFICATE-----
    ///
    /// This key can only be used to verify JWTs.
    ///
    /// - parameters:
    ///     - pem: Contents of pem file.
    public static func certificate(pem string: String) throws -> RSAKey {
        let cert = try X509.Certificate(pemEncoded: string)
        do {
            guard let publicKey = _RSA.Signing.PublicKey(cert.publicKey) else {
                throw RSAError.keyInitializationFailure
            }
            return RSAKey(publicKey: publicKey)
        } catch CryptoKitError.incorrectParameterSize {
            throw RSAError.keySizeTooSmall
        }
    }

    /// Creates RSAKey from public certificate pem file.
    ///
    /// Certificate pem files look like:
    ///
    ///     -----BEGIN CERTIFICATE-----
    ///     MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
    ///     ...
    ///     aX4rbSL49Z3dAQn8vQIDAQAB
    ///     -----END CERTIFICATE-----
    ///
    /// This key can only be used to verify JWTs.
    ///
    /// - parameters:
    ///     - pem: Contents of pem file.
    public static func certificate(pem data: some DataProtocol) throws -> RSAKey {
        let string = String(decoding: data, as: UTF8.self)
        return try certificate(pem: string)
    }

    /// Creates RSAKey from private key pem file.
    ///
    /// Private key pem files look like:
    ///
    ///     -----BEGIN PRIVATE KEY-----
    ///     MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
    ///     ...
    ///     aX4rbSL49Z3dAQn8vQIDAQAB
    ///     -----END PRIVATE KEY-----
    ///
    /// This key can be used to verify and sign JWTs.
    ///
    /// - parameters:
    ///     - pem: Contents of pem file.
    public static func `private`(pem string: String) throws -> RSAKey {
        do {
            return try RSAKey(privateKey: .init(pemRepresentation: string))
        } catch CryptoKitError.incorrectParameterSize {
            throw RSAError.keySizeTooSmall
        }
    }

    /// Creates RSAKey from private key pem file.
    ///
    /// Private key pem files look like:
    ///
    ///     -----BEGIN PRIVATE KEY-----
    ///     MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
    ///     ...
    ///     aX4rbSL49Z3dAQn8vQIDAQAB
    ///     -----END PRIVATE KEY-----
    ///
    /// This key can be used to verify and sign JWTs.
    ///
    /// - parameters:
    ///     - pem: Contents of pem file.
    public static func `private`<Data>(pem data: Data) throws -> RSAKey
        where Data: DataProtocol
    {
        let string = String(decoding: data, as: UTF8.self)
        return try self.private(pem: string)
    }

    let type: KeyType

    let publicKey: _RSA.Signing.PublicKey?
    let privateKey: _RSA.Signing.PrivateKey?

    init(publicKey: _RSA.Signing.PublicKey) {
        type = .public
        self.publicKey = publicKey
        privateKey = nil
    }

    init(privateKey: _RSA.Signing.PrivateKey) {
        type = .private
        publicKey = privateKey.publicKey
        self.privateKey = privateKey
    }

    /// Initializes a new RSA key instance with modulus, exponent, and an optional private exponent.
    ///
    /// This convenience initializer creates an RSA key using the modulus, exponent, and an optional private exponent.
    /// All these parameters are expected to be base64 URL encoded strings.
    /// If the private exponent is provided, the initializer creates an RSA private key. Otherwise, it initializes an RSA public key.
    ///
    /// - Parameters:
    ///   - modulus: The modulus of the RSA key, represented as a base64 URL encoded string.
    ///   - exponent: The exponent of the RSA key, represented as a base64 URL encoded string.
    ///   - privateExponent: An optional base64 URL encoded string representing the private exponent of the RSA key. If this parameter is nil, only a public key is generated. Defaults to `nil`.
    ///
    /// - Throws:
    ///   - `JWTError.generic` with the identifier "RSAKey" if either the modulus or exponent cannot be decoded from their base64 URL encoded strings.
    ///   - `RSAError.keyInitializationFailure` if there is a failure in initializing the RSA key, especially when the private key components are involved.
    ///
    /// - Note:
    ///   - The provided modulus and exponent are key components for creating RSA public keys.
    ///   - The private exponent is an additional parameter required for creating RSA private keys.
    public convenience init(
        modulus: String,
        exponent: String,
        privateExponent: String? = nil
    ) throws {
        func decode(_ string: String) throws -> Data {
            guard let data = string.base64URLDecodedData() else {
                throw JWTError.generic(identifier: "RSAKey", reason: "Unable to decode base64url string: \(string)")
            }
            return data
        }

        let n = try decode(modulus)
        let e = try decode(exponent)
        let d = try privateExponent.map(decode)

        var privateKey: _RSA.Signing.PrivateKey
        if let d {
            guard let privateKeyDER = try RSAKey.calculatePrivateDER(n: n, e: e, d: d) else {
                throw RSAError.keyInitializationFailure
            }
            var serializer = DER.Serializer()
            try privateKeyDER.serialize(into: &serializer)
            privateKey = try _RSA.Signing.PrivateKey(derRepresentation: serializer.serializedBytes)
            self.init(privateKey: privateKey)
        } else {
            let publicKeyDER = try RSAKey.calculateDER(n: n, e: e)
            var serializer = DER.Serializer()
            try publicKeyDER.serialize(into: &serializer)
            let publicKey = try _RSA.Signing.PublicKey(derRepresentation: serializer.serializedBytes)
            self.init(publicKey: publicKey)
        }
    }
}
