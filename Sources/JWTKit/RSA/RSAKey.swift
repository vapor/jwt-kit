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
        let string = String(decoding: data, as: UTF8.self)

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

extension RSAKey {
    func calculateDer<Data>(modulus: Data, exponent: Data) -> [UInt8] 
        where Data: DataProtocol
    {
        var modulus = BigInt(_uncheckedWords: [UInt8](modulus).map { UInt($0) })
        let exponent = BigInt(_uncheckedWords: [UInt8](exponent).map { UInt($0) })

        // Ensure the modulus is positive by adding a leading zero if needed
        if modulus._isNegative {
            modulus = BigInt(0) - modulus
        }

        // Get the length of the modulus and exponent
        // - Adding 7 ensures that you round up to the nearest multiple of 8 bits
        // - Righ-Shifting by 3 (dividing by 8) converts the number of bits to bytes
        let modulusLengthOctets = (modulus.bitWidth + 7) >> 3
        let exponentLengthOctets = (exponent.bitWidth + 7) >> 3

        // The value 15 seems to account for the byte lengths of the ASN.1 DER tags, lengths, 
        // and other components that are added as part of the encoding structure
        let totalLengthOctets = 15 + modulusLengthOctets + exponentLengthOctets

        // Create a buffer to hold the DER encoded key
        var buffer = [UInt8](repeating: 0, count: totalLengthOctets)

        // Container type and size
        buffer[0] = 0x30
        encodeLength(totalLengthOctets - 2, into: &buffer)

        // Integer type and size for modulus
        buffer[0] = 0x02
        encodeLength(modulusLengthOctets, into: &buffer)

        // Exponent
        buffer[0] = 0x02
        encodeLength(exponentLengthOctets, into: &buffer)
        
        return buffer
    }
}

extension RSAKey {
    private func encodeLength(_ length: Int, into buffer: inout [UInt8]) {
        if length < 128 {
            buffer.append(UInt8(length))
        } else {
            buffer.append(UInt8(length >> 8 | 0x80))
            buffer.append(contentsOf: [UInt8(length & 0xff)])
        }
    }
}
