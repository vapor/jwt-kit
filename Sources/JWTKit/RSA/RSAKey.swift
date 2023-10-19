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
        do {
            return try RSAKey(certificate: .init(pemEncoded: string))
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
    let certificate: X509.Certificate?

    public init(publicKey: _RSA.Signing.PublicKey) {
        type = .public
        self.publicKey = publicKey
        privateKey = nil
        certificate = nil
    }

    public init(privateKey: _RSA.Signing.PrivateKey) {
        type = .private
        publicKey = privateKey.publicKey
        self.privateKey = privateKey
        certificate = nil
    }

    public init(certificate: X509.Certificate) {
        type = .certificate
        publicKey = .init(certificate.publicKey)
        privateKey = nil
        self.certificate = certificate
    }

    public convenience init(
        modulus: String,
        exponent: String,
        privateExponent: String? = nil
    ) throws {
        func decode(_ string: String) throws -> Data {
            guard let data = string.base64URLDecodedData() else {
                throw RSAError.keyInitializationFailure
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
            return
        }
        let publicKeyDER = try RSAKey.calculateDER(n: n, e: e)
        var serializer = DER.Serializer()
        try publicKeyDER.serialize(into: &serializer)
        let publicKey = try _RSA.Signing.PublicKey(derRepresentation: serializer.serializedBytes)
        self.init(publicKey: publicKey)
    }
}
