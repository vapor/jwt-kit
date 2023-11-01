import _CryptoExtras
import Crypto
import Foundation
import SwiftASN1
import X509

public struct RSAKey: Sendable {
    /// Creates ``RSAKey`` from public key PEM file.
    ///
    /// Public key PEM files look like:
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
    ///     - pem: Contents of PEM file.
    public static func `public`(pem string: String) throws -> RSAKey {
        do {
            return try RSAKey(publicKey: .init(pemRepresentation: string))
        } catch CryptoKitError.incorrectParameterSize {
            throw RSAError.keySizeTooSmall
        }
    }

    /// Creates ``RSAKey`` from public key PEM file.
    ///
    /// Public key PEM files look like:
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
    ///     - pem: Contents of PEM file.
    public static func `public`(pem data: some DataProtocol) throws -> RSAKey {
        let string = String(decoding: data, as: UTF8.self)
        return try self.public(pem: string)
    }

    /// Creates ``RSAKey`` from public certificate PEM file.
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

    /// Creates ``RSAKey`` from public certificate PEM file.
    ///
    /// Certificate PEM files look like:
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
    ///     - pem: Contents of PEM file.
    public static func certificate(pem data: some DataProtocol) throws -> RSAKey {
        let string = String(decoding: data, as: UTF8.self)
        return try certificate(pem: string)
    }

    /// Creates ``RSAKey`` from private key PEM file.
    ///
    /// Private key PEM files look like:
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
    ///     - pem: Contents of PEM file.
    public static func `private`(pem string: String) throws -> RSAKey {
        do {
            return try RSAKey(privateKey: .init(pemRepresentation: string))
        } catch CryptoKitError.incorrectParameterSize {
            throw RSAError.keySizeTooSmall
        }
    }

    /// Creates ``RSAKey`` from private key pem file.
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
    public static func `private`(pem data: some DataProtocol) throws -> RSAKey {
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
    ///   - ``JWTError/generic`` with the identifier `RSAKey`` if either the modulus or exponent cannot be decoded from their base64 URL encoded strings.
    ///   - ``RSAError/keyInitializationFailure`` if there is a failure in initializing the RSA key, especially when the private key components are involved.
    ///
    /// - Note:
    ///   - The provided modulus and exponent are key components for creating RSA public keys.
    ///   - The private exponent is an additional parameter required for creating RSA private keys.
    public init(
        modulus: String,
        exponent: String,
        privateExponent: String? = nil
    ) throws {
        // Helper function to decode base64URL strings
        func decode(_ string: String) throws -> Data {
            guard let data = string.base64URLDecodedData() else {
                throw JWTError.generic(identifier: "RSAKey", reason: "Unable to decode base64url string: \(string)")
            }
            return data
        }

        // Decoding input strings
        let n = try decode(modulus)
        let e = try decode(exponent)
        let d = try privateExponent.map(decode)

        // Serializer to be used for DER serialization
        var serializer = DER.Serializer()

        // Creating key based on the presence of a private exponent
        if let d = d, let privateKeyDER = try? RSAKey.calculatePrivateDER(n: n, e: e, d: d) {
            try privateKeyDER.serialize(into: &serializer)
            let privateKey = try _RSA.Signing.PrivateKey(derRepresentation: serializer.serializedBytes)
            self.init(privateKey: privateKey)
        } else if let publicKeyDER = try? RSAKey.calculateDER(n: n, e: e) {
            try publicKeyDER.serialize(into: &serializer)
            let publicKey = try _RSA.Signing.PublicKey(derRepresentation: serializer.serializedBytes)
            self.init(publicKey: publicKey)
        } else {
            throw RSAError.keyInitializationFailure
        }
    }
}
