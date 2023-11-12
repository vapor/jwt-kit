import BigInt

package struct PrimeGenerator {
    /// The following algorithm recovers the prime factors of a modulus, given the public and private exponents.
    /// The algorithm is based on Fact 1 in [Boneh 1999].
    package static func calculatePrimeFactors(
        n: BigUInt, e: BigUInt, d: BigUInt
    ) throws -> (p: BigUInt, q: BigUInt) {
        let k = (d * e) - 1

        guard k & 1 == 0 else {
            throw RSAError.keyInitializationFailure
        }

        let t = k.trailingZeroBitCount, r = k >> t

        var y: BigUInt = 0
        var i = 1

        // If the prime factors are not revealed after 100 iterations,
        // then the probability is overwhelming that the modulus is not the product of two prime factors,
        // or that the public and private exponents are not consistent with each other.
        // var randomGenerator = generator
        while i <= 100 {
            let g = BigUInt.randomInteger(lessThan: n - 1)
            y = g.power(r, modulus: n)

            guard y != 1, y != n - 1 else {
                continue
            }

            var j = 1
            var x: BigUInt

            while j <= t &- 1 {
                x = y.power(2, modulus: n)

                guard x != 1, x != n - 1 else {
                    break
                }

                y = x
                j &+= 1
            }

            x = y.power(2, modulus: n)
            if x == 1 {
                let p = (y - 1).greatestCommonDivisor(with: n)
                let q = n / p

                return (p, q)
            }
            i &+= 1
        }

        throw RSAError.keyInitializationFailure
    }
}
