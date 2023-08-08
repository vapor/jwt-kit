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
    func calculateDER<Data>(modulus: Data, exponent: Data) -> [UInt8] 
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
    
    func calculatePrivateDER(n: String, e: String, d: String) throws -> DERSerializable? {
        // Use the CRT algorithm to calculate the private key
        guard 
            let n = BigInt(n),
            let e = BigInt(e),
            let d = BigInt(d) 
        else {
            return nil
        }

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
    private func encodeLength(_ length: Int, into buffer: inout [UInt8]) {
        if length < 128 {
            buffer.append(UInt8(length))
        } else {
            buffer.append(UInt8(length >> 8 | 0x80))
            buffer.append(contentsOf: [UInt8(length & 0xff)])
        }
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
