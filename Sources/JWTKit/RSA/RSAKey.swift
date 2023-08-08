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
        try RSAKey(certificate: try X509.Certificate(pemEncoded: string))
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
    let certificate: X509.Certificate?

    public init(
        publicKey: _RSA.Signing.PublicKey? = nil, 
        privateKey: _RSA.Signing.PrivateKey? = nil, 
        certificate: X509.Certificate? = nil
    ) throws {
        guard publicKey != nil || privateKey != nil || certificate != nil else {
            throw RSAError.keyInitializationFailure
        }
        self.type = publicKey != nil ? .public : privateKey != nil ? .private : .certificate
        self.publicKey = publicKey
        self.privateKey = privateKey
        self.certificate = certificate
    }
}

extension RSAKey {
    func calculatePrivateDER(n: String, e: String, d: String) throws -> DERSerializable? {
        guard 
            let n = BigInt(n),
            let e = BigInt(e),
            let d = BigInt(d) 
        else {
            return nil
        }

        // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br1.pdf        

        let (p, q) = try PrimeGenerator.calculatePrimeFactors(n: n, e: e, d: d)

        // https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm

        let dp = d % (p - 1)
        let dq = d % (q - 1)

        guard let qInv = q.modularInverse(p) else {
            return nil
        }

        let key = RSAPrivateKeyASN1(
            modulus: n.words.withUnsafeBytes(ArraySlice.init),
            publicExponent: e.words.withUnsafeBytes(ArraySlice.init),
            privateExponent: d.words.withUnsafeBytes(ArraySlice.init),
            prime1: p.words.withUnsafeBytes(ArraySlice.init),
            prime2: q.words.withUnsafeBytes(ArraySlice.init),
            exponent1: dp.words.withUnsafeBytes(ArraySlice.init),
            exponent2: dq.words.withUnsafeBytes(ArraySlice.init),
            coefficient: qInv.words.withUnsafeBytes(ArraySlice.init)
        )

        return key
    }
}

extension RSAKey {
    struct RSAPrivateKeyASN1: DERSerializable {
        let version: UInt8 = 0
        let modulus: ArraySlice<UInt8>
        let publicExponent: ArraySlice<UInt8>
        let privateExponent: ArraySlice<UInt8>
        let prime1: ArraySlice<UInt8>
        let prime2: ArraySlice<UInt8>
        let exponent1: ArraySlice<UInt8>
        let exponent2: ArraySlice<UInt8>
        let coefficient: ArraySlice<UInt8>

        func serialize(into coder: inout DER.Serializer) throws {}
        
        func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
            try coder.appendConstructedNode(identifier: identifier) { coder in
                try coder.serialize(self.version)
                try coder.serialize(self.modulus)
                try coder.serialize(self.publicExponent)
                try coder.serialize(self.privateExponent)
                try coder.serialize(self.prime1)
                try coder.serialize(self.prime2)
                try coder.serialize(self.exponent1)
                try coder.serialize(self.exponent2)
                try coder.serialize(self.coefficient)
            }
        }
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
