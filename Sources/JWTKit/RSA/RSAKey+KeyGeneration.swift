import SwiftASN1
import _CryptoExtras

extension RSAKey {
    /// Creates a new private key using modulus, exponent and private exponent.
    static func calculatePrivateDER(n: String, e: String, d: String) throws -> DERSerializable? {
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

    /// Creates a new public key using modulus and exponent.
    static func calculateDER(n: String, e: String) throws -> [UInt8] {
        guard 
            var n = BigInt(n), 
            let e = BigInt(e) 
        else {
            throw RSAError.keyInitializationFailure
        }

        // Ensure the modulus is positive by adding a leading zero if needed
        if n._isNegative {
            n = BigInt(0) - n
        }

        // Get the length of the modulus and exponent
        // - Adding 7 ensures that you round up to the nearest multiple of 8 bits
        // - Righ-Shifting by 3 (dividing by 8) converts the number of bits to bytes
        let modulusLengthOctets = (n.bitWidth + 7) >> 3
        let exponentLengthOctets = (e.bitWidth + 7) >> 3

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

    private static func encodeLength(_ length: Int, into buffer: inout [UInt8]) {
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

        func serialize(into coder: inout DER.Serializer) throws {
            try coder.appendConstructedNode(identifier: .sequence) { coder in
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