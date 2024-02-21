@_implementationOnly import CJWTKitBoringSSL
import Foundation

public final class RSAKey: OpenSSLKey {
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
        try .public(pem: [UInt8](string.utf8))
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
        let pkey = try self.load(pem: data) { bio in
            CJWTKitBoringSSL_PEM_read_bio_PUBKEY(bio, nil, nil, nil)
        }
        defer { CJWTKitBoringSSL_EVP_PKEY_free(pkey) }

        guard let c = CJWTKitBoringSSL_EVP_PKEY_get1_RSA(pkey) else {
            throw JWTError.signingAlgorithmFailure(RSAError.keyInitializationFailure)
        }
        return self.init(c, .public)
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
        try self.certificate(pem: [UInt8](string.utf8))
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
        let x509 = try self.load(pem: data) { bio in
            CJWTKitBoringSSL_PEM_read_bio_X509(bio, nil, nil, nil)
        }
        defer { CJWTKitBoringSSL_X509_free(x509) }
        let pkey = CJWTKitBoringSSL_X509_get_pubkey(x509)
        defer { CJWTKitBoringSSL_EVP_PKEY_free(pkey) }

        guard let c = CJWTKitBoringSSL_EVP_PKEY_get1_RSA(pkey) else {
            throw JWTError.signingAlgorithmFailure(RSAError.keyInitializationFailure)
        }
        return self.init(c, .public)
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
        try .private(pem: [UInt8](string.utf8))
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
        let pkey = try self.load(pem: data) { bio in
            CJWTKitBoringSSL_PEM_read_bio_PrivateKey(bio, nil, nil, nil)
        }
        defer { CJWTKitBoringSSL_EVP_PKEY_free(pkey) }

        guard let c = CJWTKitBoringSSL_EVP_PKEY_get1_RSA(pkey) else {
            throw JWTError.signingAlgorithmFailure(RSAError.keyInitializationFailure)
        }
        return self.init(c, .private)
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

        guard let rsa = CJWTKitBoringSSL_RSA_new() else {
            return nil
        }

        CJWTKitBoringSSL_RSA_set0_key(
            rsa,
            CJWTKitBoringSSL_BN_bin2bn(n, numericCast(n.count), nil),
            CJWTKitBoringSSL_BN_bin2bn(e, numericCast(e.count), nil),
            d.flatMap { CJWTKitBoringSSL_BN_bin2bn($0, numericCast($0.count), nil) }
        )
        self.init(rsa, d == nil ? .public : .private)
    }

    enum KeyType {
        case `public`, `private`
    }

    let type: KeyType

    internal var c: OpaquePointer {
        return CJWTKitBoringSSL_EVP_PKEY_get1_RSA(self.cRaw)
    }
    
    let cRaw: OpaquePointer

    init(_ c: OpaquePointer, _ type: KeyType) {
        self.type = type
        self.cRaw = CJWTKitBoringSSL_EVP_PKEY_new()
        CJWTKitBoringSSL_EVP_PKEY_assign_RSA(cRaw, c)
    }

    deinit {
        CJWTKitBoringSSL_EVP_PKEY_free(self.c)
    }
}
