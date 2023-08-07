import _CryptoExtras
import Foundation
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
    public static func `public`(pem string: String) throws -> _RSA.Signing.PublicKey {
        try _RSA.Signing.PublicKey(pemRepresentation: string)
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
    public static func `public`<Data>(pem data: Data) throws -> _RSA.Signing.PublicKey
        where Data: DataProtocol
    {
        let string = String(decoding: data, as: UTF8.self)
        return try _RSA.Signing.PublicKey(pemRepresentation: string)
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
    public static func certificate(pem string: String) throws -> X509.Certificate {
        try X509.Certificate(pemEncoded: string)
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
    public static func certificate<Data>(pem data: Data) throws -> X509.Certificate
        where Data: DataProtocol
    {
        guard let string = String(bytes: data, encoding: .utf8) else {
            throw JWTError.signingAlgorithmFailure(RSAError.keyInitializationFailure)
        }

        return try self.certificate(pem: string)
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
    public static func `private`(pem string: String) throws -> _RSA.Signing.PrivateKey {
        try _RSA.Signing.PrivateKey(pemRepresentation: string)
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
    public static func `private`<Data>(pem data: Data) throws -> _RSA.Signing.PrivateKey
        where Data: DataProtocol
    {
        let string = String(decoding: data, as: UTF8.self) 

        return try self.private(pem: string)
    }

    public convenience init?(
        modulus: String,
        exponent: String,
        privateExponent: String? = nil
    ) {
        func decode(_ string: String) -> [UInt8] {
            return [UInt8](string.utf8).base64URLDecodedBytes()
        }
        let n = decode(modulus)
        let e = decode(exponent)
        let d = privateExponent.flatMap { decode($0) }

        // ...
    }

    let type: KeyType

    let publicKey: _RSA.Signing.PublicKey?
    let privateKey: _RSA.Signing.PrivateKey?

    public init(publicKey: _RSA.Signing.PublicKey) {
        self.type = .public
        self.publicKey = publicKey
        self.privateKey = nil
    }

    public init(privateKey: _RSA.Signing.PrivateKey) {
        self.type = .private
        self.publicKey = nil
        self.privateKey = privateKey
    }
}
