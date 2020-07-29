import CJWTKitBoringSSL
import struct Foundation.Data

public final class RSAKey: OpenSSLKey {
    public static func `public`(pem string: String) throws -> RSAKey {
        try .public(pem: [UInt8](string.utf8))
    }

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

    public static func `private`(pem string: String) throws -> RSAKey {
        try .private(pem: [UInt8](string.utf8))
    }

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
    let c: UnsafeMutablePointer<RSA>

    init(_ c: UnsafeMutablePointer<RSA>, _ type: KeyType) {
        self.type = type
        self.c = c
    }

    deinit {
        CJWTKitBoringSSL_RSA_free(self.c)
    }
}
