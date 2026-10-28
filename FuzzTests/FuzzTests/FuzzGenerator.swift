import Foundation
import JWTKit

/// Deterministic PRNG so fuzz inputs are reproducible.
struct SplitMix64: RandomNumberGenerator {
    private var state: UInt64
    init(seed: UInt64) { state = seed }
    mutating func next() -> UInt64 {
        state &+= 0x9E37_79B9_7F4A_7C15
        var z = state
        z = (z ^ (z >> 30)) &* 0xBF58_476D_1CE4_E5B9
        z = (z ^ (z >> 27)) &* 0x94D0_49BB_1331_11EB
        return z ^ (z >> 31)
    }
}

// Manual JSON generation to avoid any guards in JSONEncoder so we can generate invalid JSON for fuzzing
struct JWTFuzzGenerator {
    private var rng: SplitMix64

    init(seed: UInt64) { rng = SplitMix64(seed: seed) }

    mutating func nextUInt(_ bound: UInt64) -> UInt64 { rng.next() % bound }
    mutating func nextBool() -> Bool { rng.next() & 1 == 0 }

    mutating func jsonValue(depth: Int) -> String {
        let kinds: UInt64 = depth > 0 ? 8 : 6
        switch nextUInt(kinds) {
        case 0: return jsonNumber()
        case 1: return jsonString()
        case 2: return "true"
        case 3: return "false"
        case 4: return "null"
        case 5: return jsonNumber()
        case 6: return jsonArray(depth: depth)
        default: return jsonObject(depth: depth)
        }
    }

    mutating func jsonArray(depth: Int) -> String {
        let count = Int(nextUInt(4))
        let elements = (0..<count).map { _ in jsonValue(depth: depth - 1) }
        return "[\(elements.joined(separator: ","))]"
    }

    mutating func jsonObject(depth: Int) -> String {
        let count = Int(nextUInt(4))
        var pairs: [String] = []
        for _ in 0..<count {
            let key = (nextUInt(8) == 0 && !pairs.isEmpty) ? "dup" : jsonKey()
            pairs.append("\(key):\(jsonValue(depth: depth - 1))")
        }
        return "{\(pairs.joined(separator: ","))}"
    }

    private mutating func jsonKey() -> String {
        switch nextUInt(6) {
        case 0: return "\"\""
        case 1: return "\"\(randomIdentifier(length: 1 + Int(nextUInt(12))))\""
        case 2: return "\"alg\""  // collide with reserved names
        case 3: return "\"kid\""
        case 4: return "\"\(randomIdentifier(length: 512))\""  // very long key
        default: return "\"\(randomIdentifier(length: 1 + Int(nextUInt(4))))\""
        }
    }

    mutating func jsonNumber() -> String {
        switch nextUInt(14) {
        case 0: return String(Int64(bitPattern: rng.next()))
        case 1: return String(rng.next() >> nextUInt(64))
        case 2: return Self.intBoundaries[Int(nextUInt(UInt64(Self.intBoundaries.count)))]
        case 3: return "\(sign())1e\(nextUInt(400))"
        case 4: return "\(sign())1e-\(nextUInt(400))"
        case 5: return "\(sign())\(nextUInt(1000)).\(nextUInt(1_000_000))"
        case 6: return "\(sign())\(String(repeating: "9", count: 1 + Int(nextUInt(400))))"
        case 7: return "\(sign())\(UInt64(1) << (48 + nextUInt(16)))"  // straddles 2^53
        case 8: return "0"
        case 9: return "-0"
        case 10: return "\(sign())\(nextUInt(1000))e\(nextBool() ? "" : "-")\(nextUInt(320))"
        case 11: return "\(sign())0.\(String(repeating: "0", count: Int(nextUInt(320))))1"
        case 12:
            let value = Double(bitPattern: rng.next())
            return value.isFinite ? String(value) : "1.5"
        default: return Self.malformedNumbers[Int(nextUInt(UInt64(Self.malformedNumbers.count)))]
        }
    }

    private mutating func sign() -> String { nextBool() ? "" : "-" }

    static let intBoundaries: [String] = [
        "9223372036854775807",  // Int.max
        "9223372036854775808",  // Int.max + 1 — the plain-literal overflow
        "9223372036854775809",
        "-9223372036854775808",  // Int.min
        "-9223372036854775809",  // Int.min - 1
        "18446744073709551615",  // UInt64.max
        "18446744073709551616",
        "9007199254740992",  // 2^53
        "9007199254740993",  // 2^53 + 1 — first integer Double cannot represent
        "-9007199254740993",
        "4503599627370496",  // 2^52
        "1e308", "-1e308", "1e309", "-1e309", "1e400", "1e-400",
        "1.7976931348623157e308",  // Double.greatestFiniteMagnitude
        "1.7976931348623159e308",  // just past it — overflows to infinity
        "5e-324",  // Double.leastNonzeroMagnitude
    ]

    static let malformedNumbers: [String] = [
        "01", "+1", ".5", "5.", "1e", "1e+", "--1", "1.2.3", "0x10", "Infinity",
        "-Infinity", "NaN", "1_000", "1e999999999999999999",
    ]

    mutating func jsonString() -> String {
        switch nextUInt(9) {
        case 0: return #""""#
        case 1: return "\"\(randomIdentifier(length: 1 + Int(nextUInt(24))))\""
        case 2: return #""\u0000""#  // escaped NUL
        case 3: return #""\ud800""#  // lone high surrogate
        case 4: return #""\udfff""#  // lone low surrogate
        case 5: return #""\\\"\/\b\f\n\r\t""#  // every legal escape
        case 6: return "\"\(String(repeating: "A", count: 4096))\""  // long
        case 7: return #""😀🇬🇧éé""#  // multi-scalar / combining
        default: return #""\uZZZZ""#  // malformed escape
        }
    }

    private mutating func randomIdentifier(length: Int) -> String {
        let alphabet = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-")
        return String((0..<length).map { _ in alphabet[Int(nextUInt(UInt64(alphabet.count)))] })
    }

    mutating func headerJSON(validAlg: Bool = true) -> String {
        var pairs: [String] = []
        if validAlg {
            pairs.append(#""alg":"HS256""#)
        } else if nextBool() {
            pairs.append("\"alg\":\(jsonValue(depth: 1))")
        }
        if nextBool() { pairs.append(#""typ":"JWT""#) }
        if nextBool() { pairs.append("\"kid\":\(jsonValue(depth: 1))") }
        let extras = Int(nextUInt(4))
        for index in 0..<extras {
            pairs.append("\"x\(index)\":\(jsonValue(depth: Int(nextUInt(4))))")
        }
        return "{\(pairs.joined(separator: ","))}"
    }

    mutating func payloadJSON() -> String {
        var pairs: [String] = [#""sub":"1234567890""#, "\"exp\":\(2_000_000_000)"]
        let extras = Int(nextUInt(3))
        for index in 0..<extras {
            pairs.append("\"p\(index)\":\(jsonValue(depth: Int(nextUInt(3))))")
        }
        return "{\(pairs.joined(separator: ","))}"
    }

    /// Signature is junk, we're checking header and payload parsing only. The signature is never verified.
    mutating func token(header: String, payload: String, signature: String? = nil) -> [UInt8] {
        let sig = signature ?? randomIdentifier(length: 43)
        return Array("\(Self.base64URL(header)).\(Self.base64URL(payload)).\(sig)".utf8)
    }

    /// A token with a genuinely valid signature, to fuzz code during and after validation
    static func signedToken(
        header: String, payload: String, using algorithm: some JWTAlgorithm
    ) throws -> [UInt8] {
        let signingInput = "\(base64URL(header)).\(base64URL(payload))"
        let signature = try algorithm.sign(Array(signingInput.utf8))
        return Array("\(signingInput).\(base64URL(signature))".utf8)
    }

    static func nested(depth: Int, style: NestingStyle) -> String {
        switch style {
        case .arrays:
            return String(repeating: "[", count: depth) + String(repeating: "]", count: depth)
        case .objects:
            return String(repeating: #"{"a":"#, count: depth) + "0" + String(repeating: "}", count: depth)
        case .mixed:
            var out = ""
            for index in 0..<depth { out += index.isMultiple(of: 2) ? "[" : #"{"a":"# }
            out += "0"
            for index in (0..<depth).reversed() { out += index.isMultiple(of: 2) ? "]" : "}" }
            return out
        }
    }

    enum NestingStyle: CaseIterable, Sendable { case arrays, objects, mixed }

    static func base64URL(_ string: String) -> String {
        base64URL(Array(string.utf8))
    }

    static func base64URL(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    mutating func mutate(_ bytes: inout [UInt8]) {
        for _ in 0..<(1 + Int(nextUInt(4))) {
            guard !bytes.isEmpty else {
                bytes.append(UInt8(truncatingIfNeeded: rng.next()))
                continue
            }
            let index = Int(nextUInt(UInt64(bytes.count)))
            switch nextUInt(8) {
            case 0: bytes[index] ^= UInt8(1) << UInt8(nextUInt(8))
            case 1: bytes[index] = UInt8(truncatingIfNeeded: rng.next())
            case 2: bytes.removeLast(bytes.count - index)
            case 3: bytes.insert(UInt8(truncatingIfNeeded: rng.next()), at: index)
            case 4: bytes.remove(at: index)
            case 5: bytes[index] = UInt8(ascii: ".")  // extra separator
            case 6: bytes.removeAll { $0 == UInt8(ascii: ".") }  // drop separators
            default: bytes[index] = 0x80 | UInt8(truncatingIfNeeded: rng.next())  // invalid UTF-8
            }
        }
    }

    mutating func randomBytes(maxLength: Int) -> [UInt8] {
        let length = Int(nextUInt(UInt64(maxLength)))
        return (0..<length).map { _ in UInt8(truncatingIfNeeded: rng.next()) }
    }

    /// A random `JWTHeaderField` restricted to values that are expected to survive
    /// an encode → decode round trip unchanged.
    ///
    /// Two exclusions are deliberate, and each has its own dedicated test in
    /// ``HeaderParsingRegressionTests`` documenting why:
    ///
    /// - Integers outside ±2^53 lose precision, because decoding routes every
    ///   number through `Double`.
    /// - Integral doubles (`2.0`) come back as `.int(2)`, because the decoder
    ///   classifies by value rather than by JSON syntax.
    mutating func roundTrippableField(depth: Int) -> JWTHeaderField {
        let kinds: UInt64 = depth > 0 ? 8 : 6
        switch nextUInt(kinds) {
        case 0: return .null
        case 1: return .bool(nextBool())
        case 2: return .int(Int(Int64(bitPattern: rng.next()) % 9_007_199_254_740_992))
        case 3: return .decimal(nonIntegralDouble())
        case 4: return .string(randomIdentifier(length: Int(nextUInt(32))))
        case 5: return .int(0)
        case 6:
            let count = Int(nextUInt(4))
            return .array((0..<count).map { _ in roundTrippableField(depth: depth - 1) })
        default:
            let count = Int(nextUInt(4))
            var object: [String: JWTHeaderField] = [:]
            for _ in 0..<count {
                object[randomIdentifier(length: 1 + Int(nextUInt(8)))] = roundTrippableField(depth: depth - 1)
            }
            return .object(object)
        }
    }

    private mutating func nonIntegralDouble() -> Double {
        var value = Double(bitPattern: rng.next())
        if !value.isFinite || value.truncatingRemainder(dividingBy: 1) == 0 {
            value = Double(nextUInt(1_000_000)) + 0.5
        }
        return value
    }
}
