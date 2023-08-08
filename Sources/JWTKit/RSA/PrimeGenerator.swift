import Foundation

struct PrimeGenerator {
    public static func generatePrimeNumber(bitLength: Int) -> BigInt {
        var random: BigInt
        repeat {
            random = BigInt.randomInteger(withExactWidth: bitLength)
        } while !millerRabinTest(on: random, iterations: 40)
        return random
    }

    public static func millerRabinTest(on number: BigInt, iterations: Int) -> Bool {
        if number == 2 || number == 3 {
            return true
        }
        guard number % 2 == 1 else {
            return false
        }

        var d = number - 1
        var s = 0
        
        while d % 2 == 0 {
            d /= 2
            s += 1
        }

        for _ in 0..<iterations {
            let a = BigInt.randomInteger(lessThan: number - 3) + 2
            var x = powerMod(a, d, number)
            if x == 1 || x == number - 1 {
                continue
            }
            for _ in 0..<s {
                x = powerMod(x, 2, number)
                if x == 1 {
                    return false
                }
                if x == number - 1 {
                    break
                }
            }
            if x != number - 1 {
                return false
            }
        }

        return true
    }

    private static func powerMod(_ base: BigInt, _ exponent: BigInt, _ modulus: BigInt) -> BigInt {
        var base = base
        var exponent = exponent
        var result = BigInt(1)

        while exponent > 0 {
            if exponent % 2 == 1 {
                result = (result * base) % modulus
            }
            exponent /= 2
            base = (base * base) % modulus
        }

        return result
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
    
    var leadingZeroBitCount: Int {
        var count = 0
        var number = self
        while number > 0 {
            number /= 2
            count += 1
        }
        return Swift.max(0, bitWidth - count)
    }
}