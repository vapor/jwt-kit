import _CryptoExtras
import Foundation
import X509
import SwiftASN1

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
        self.type = publicKey != nil ? .public : privateKey != nil ? .private : .certificate
        self.publicKey = publicKey
        self.privateKey = privateKey
    }

    public convenience init?(
        modulus: String,
        exponent: String,
        privateExponent: String? = nil
    ) throws {
        var privateKey: _RSA.Signing.PrivateKey? = nil
        if let privateExponent {
            guard let privateKeyDER = try RSAKey.calculatePrivateDER(n: modulus, e: exponent, d: privateExponent) else {
                throw RSAError.keyInitializationFailure
            }
            var serializer = DER.Serializer()
            try privateKeyDER.serialize(into: &serializer)
            privateKey = try _RSA.Signing.PrivateKey(derRepresentation: serializer.serializedBytes)
        }
        try self.init(
            publicKey: privateKey?.publicKey ?? _RSA.Signing.PublicKey(
                derRepresentation: RSAKey.calculateDER(n: modulus, e: exponent)
            ),
            privateKey: privateKey
        )
    }
}

extension BigInt {
    /// The modular multiplicative inverse of a number `a` modulo `m` is a number `b` such that:
    /// a b ≡ 1 (mod m)
    /// 
    /// Or in other words, such that
    /// Exists k ∈ ℤ : ab = 1 + km
    func modularInverse(_ m: BigInt) -> BigInt? {
        let (gcd, x, _) = extendedEuclideanAlgorithm(self, m)

        guard gcd == 1 else {
            return nil
        }

        return (x % m + m) % m
    }

    /// The extended Euclidean algorithm is an extension to the Euclidean algorithm,
    /// and computes, in addition to the greatest common divisor of integers a and b,
    /// also the coefficients of Bézout's identity, which are integers x and y such that:
    /// ax + by = gcd(a, b)
    private func extendedEuclideanAlgorithm(_ a: BigInt, _ b: BigInt) -> (BigInt, BigInt, BigInt) {
        if a == 0 {
            return (b, 0, 1)
        }

        let (gcd, x1, y1) = extendedEuclideanAlgorithm(b % a, a)

        let x = y1 - (b / a) * x1
        let y = x1

        return (gcd, x, y)
    }
}
