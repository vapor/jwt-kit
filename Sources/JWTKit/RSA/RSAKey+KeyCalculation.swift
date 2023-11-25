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

extension BigUInt {
    var byteArray: [UInt8] {
        // Remove any leading zero bytes (from the MSB side)
        Array(serialize().drop(while: { $0 == 0 }))
    }
}
