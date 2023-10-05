import _CryptoExtras
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
        try RSAKey(publicKey: .init(pemRepresentation: string))
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
    public static func `public`<Data>(pem data: Data) throws -> RSAKey
        where Data: DataProtocol
    {
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
        try RSAKey(publicKey: .init(pemRepresentation: string))
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
    public static func certificate<Data>(pem data: Data) throws -> RSAKey
        where Data: DataProtocol
    {
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
        try RSAKey(privateKey: .init(pemRepresentation: string))
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

    public init(
        publicKey: _RSA.Signing.PublicKey? = nil,
        privateKey: _RSA.Signing.PrivateKey? = nil
    ) throws {
        guard publicKey != nil || privateKey != nil else {
            throw RSAError.keyInitializationFailure
        }
        type = publicKey != nil ? .public : privateKey != nil ? .private : .certificate
        self.publicKey = publicKey
        self.privateKey = privateKey
    }

    public convenience init(
        modulus: String,
        exponent: String,
        privateExponent: String? = nil
    ) throws {
        var privateKey: _RSA.Signing.PrivateKey?
        if let privateExponent {
            guard let privateKeyDER = try RSAKey.calculatePrivateDER(n: modulus, e: exponent, d: privateExponent) else {
                throw RSAError.keyInitializationFailure
            }
            var serializer = DER.Serializer()
            try privateKeyDER.serialize(into: &serializer)
            privateKey = try _RSA.Signing.PrivateKey(derRepresentation: serializer.serializedBytes)
        }
        let publicKeyDER = try RSAKey.calculateDER(n: modulus, e: exponent)
        var serializer = DER.Serializer()
        try publicKeyDER.serialize(into: &serializer)
        try self.init(
            publicKey: privateKey?.publicKey ?? _RSA.Signing.PublicKey(
                derRepresentation: serializer.serializedBytes
            ),
            privateKey: privateKey
        )
    }
}
