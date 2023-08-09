import Foundation

struct PrimeGenerator {
    /// The following algorithm recovers the prime factors of a modulus, given the public and private exponents. 
    /// The algorithm is based on Fact 1 in [Boneh 1999].
    public static func calculatePrimeFactors(n: BigInt, e: BigInt, d: BigInt) throws -> (p: BigInt, q: BigInt) {
        let k = (d * e) - 1

        guard k & 1 == 0 else {
            throw RSAError.keyInitializationFailure
        }

        let t = k.trailingZeroBitCount, r = k >> t

        var y: BigInt = 0
        var i = 1

        // If the prime factors are not revealed after 100 iterations, 
        // then the probability is overwhelming that the modulus is not the product of two prime factors, 
        // or that the public and private exponents are not consistent with each other.
        while i <= 100 {
            let g = BigInt.randomInteger(lessThan: n - 1)
            y = g.power(r, modulus: n)

            guard y != 1 && y != n - 1 else {
                continue
            }

            var j = 1
            var x: BigInt

            while j <= t - 1 {
                x = y.power(2, modulus: n)

                guard x != 1 else {
                    break
                }

                guard x != n - 1 else {
                    continue
                }

                y = x
                j += 1
            }

            x = y.power(2, modulus: n)
            if x == 1 {
                let p = (y - 1).gcd(with: n)
                let q = n / p

                return (p, q)
            }
            i += 1
        }

        throw RSAError.keyInitializationFailure
    }
}

extension BigInt {
    public static func randomInteger(lessThan n: BigInt) -> BigInt {
        let bitLength = n.bitWidth - n.leadingZeroBitCount
        var random: BigInt
        repeat {
            random = BigInt.randomInteger(withExactWidth: bitLength)
        } while random >= n
        return random
    }

    public static func randomInteger(withExactWidth width: Int) -> BigInt {
        let byteCount = (width + 7) / 8
        var random = BigInt()
        
        let bytes = (0..<byteCount).map { _ in UInt8.random(in: 0...UInt8.max) }
        for (index, byte) in bytes.enumerated() {
            let shiftAmount = 8 * (byteCount - index - 1)
            random |= BigInt(byte) << shiftAmount
        }
        
        return random
    }
    
    public var leadingZeroBitCount: Int {
        var n = bitWidth
        for w in words.reversed() {
            n &-= w.leadingZeroBitCount
            if w != 0 {
                break
            }
        }
        return Swift.max(0, n)
    }


    func power(_ exponent: BigInt, modulus: BigInt) -> BigInt {
        var base = self
        var exponent = exponent
        var result = BigInt(1)

        while exponent > 0 {
            if exponent.words[0] & 1 != 0 {
                result = (result * base) % modulus
            }
            exponent /= 2
            base = (base * base) % modulus
        }

        return result
    }

    func gcd(with other: BigInt) -> BigInt {
        var a = self
        var b = other

        while b != 0 {
            let t = b
            b = a % b
            a = t
        }

        return a
    }
}