import _CryptoExtras
import BigInt
import Foundation
import SwiftASN1

extension RSAKey {
    /// Creates a new private key using modulus, exponent and private exponent.
    static func calculatePrivateDER(n: Data, e: Data, d: Data) throws -> DERSerializable? {
        let n = BigUInt(n)
        let e = BigUInt(e)
        let d = BigUInt(d)

        // https://nvlpubs.nist.gov/nistpubs/SpecialPublications/NIST.SP.800-56Br1.pdf

        let (p, q) = try PrimeGenerator.calculatePrimeFactors(n: n, e: e, d: d)

        // https://en.wikipedia.org/wiki/RSA_(cryptosystem)#Using_the_Chinese_remainder_algorithm

        let dp = d % (p - 1)
        let dq = d % (q - 1)

        guard let qInv = q.inverse(p) else {
            return nil
        }

        let key = RSAPrivateKeyASN1(
            modulus: ArraySlice(n.byteArray),
            publicExponent: ArraySlice(e.byteArray),
            privateExponent: ArraySlice(d.byteArray),
            prime1: ArraySlice(p.byteArray),
            prime2: ArraySlice(q.byteArray),
            exponent1: ArraySlice(dp.byteArray),
            exponent2: ArraySlice(dq.byteArray),
            coefficient: ArraySlice(qInv.byteArray)
        )

        return key
    }

    static func calculateDER(n: Data, e: Data) throws -> DERSerializable {
        let n = BigUInt(n)
        let e = BigUInt(e)

        let key = RSAPublicKeyASN1(
            modulus: ArraySlice(n.byteArray),
            publicExponent: ArraySlice(e.byteArray)
        )

        return key
    }
}

extension RSAKey {
    /// From [RFC 8017 § A.1.2](https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1.1):
    ///
    ///    RSAPublicKey ::= SEQUENCE {
    ///        modulus           INTEGER,  -- n
    ///        publicExponent    INTEGER   -- e
    ///    }
    struct RSAPublicKeyASN1: DERSerializable {
        let modulus: ArraySlice<UInt8>
        let publicExponent: ArraySlice<UInt8>

        func serialize(into coder: inout DER.Serializer) throws {
            try coder.appendConstructedNode(identifier: .sequence) { coder in
                try coder.serialize(self.modulus)
                try coder.serialize(self.publicExponent)
            }
        }
    }
}

extension RSAKey {
    /// From [RFC 8017 § A.1.2](https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1.2):
    ///
    ///    RSAPrivateKey ::= SEQUENCE {
    ///        version           Version,
    ///        modulus           INTEGER,  -- n
    ///        publicExponent    INTEGER,  -- e
    ///        privateExponent   INTEGER,  -- d
    ///        prime1            INTEGER,  -- p
    ///        prime2            INTEGER,  -- q
    ///        exponent1         INTEGER,  -- d mod (p-1)
    ///        exponent2         INTEGER,  -- d mod (q-1)
    ///        coefficient       INTEGER,  -- (inverse of q) mod p
    ///        otherPrimeInfos   OtherPrimeInfos OPTIONAL
    ///    }
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

extension BigUInt {
    var byteArray: [UInt8] {
        // Remove any leading zero bytes (from the MSB side)
        Array(serialize().drop(while: { $0 == 0 }))
    }
}
