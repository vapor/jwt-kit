import Foundation
import JWTKit

/// Domain-directed generation.
extension JWTFuzzGenerator {
    mutating func logUniformSize(upTo maximum: Int) -> Int {
        guard maximum > 0 else { return 0 }
        let maxExponent = UInt64(Int.bitWidth - maximum.leadingZeroBitCount)
        let exponent = nextUInt(maxExponent + 1)
        let upper = min(Int(UInt64(1) << exponent), maximum)
        return Int(nextUInt(UInt64(upper) + 1))
    }

    enum DegenerateShape: CaseIterable, Sendable {
        case deepChain, wideArray, wideObject, longString, longKey, manyDuplicateKeys, sparseChain
    }

    mutating func degenerateValue() -> String {
        let shapes = DegenerateShape.allCases
        switch shapes[Int(nextUInt(UInt64(shapes.count)))] {
        case .deepChain:
            let depth = max(1, logUniformSize(upTo: 600))
            let styles = NestingStyle.allCases
            return Self.nested(depth: depth, style: styles[Int(nextUInt(UInt64(styles.count)))])
        case .wideArray:
            let count = logUniformSize(upTo: 10_000)
            return "[" + Array(repeating: "0", count: count).joined(separator: ",") + "]"
        case .wideObject:
            let count = logUniformSize(upTo: 10_000)
            return "{" + (0..<count).map { "\"k\($0)\":0" }.joined(separator: ",") + "}"
        case .longString:
            return "\"" + String(repeating: "A", count: logUniformSize(upTo: 32_768)) + "\""
        case .longKey:
            return "{\"" + String(repeating: "k", count: logUniformSize(upTo: 32_768)) + "\":0}"
        case .manyDuplicateKeys:
            let count = logUniformSize(upTo: 5_000)
            return "{" + Array(repeating: #""dup":0"#, count: count).joined(separator: ",") + "}"
        case .sparseChain:
            let depth = max(1, logUniformSize(upTo: 120))
            var out = "0"
            for _ in 0..<depth { out = "[\(out),0]" }
            return out
        }
    }

    static let registeredHeaderParameters = [
        "alg", "typ", "cty", "kid", "jku", "jwk", "x5c", "x5u", "x5t", "x5t#S256",
        "crit", "zip", "enc", "epk", "apu", "apv", "iv", "tag", "p2s", "p2c", "b64",
    ]

    static let algorithmValues = [
        "HS256", "HS384", "HS512",
        "RS256", "RS384", "RS512",
        "PS256", "PS384", "PS512",
        "ES256", "ES384", "ES512", "ES256K",
        "EdDSA", "ML-DSA-44", "ML-DSA-65", "ML-DSA-87",
        "none", "None", "NONE", "nOnE",
        "", " ", "HS256 ", " HS256", "hs256", "HS256\u{0}",
        "HS256\nRS256", "unknown", "HS999",
    ]

    static let kidValues = [
        "", " ", "a", "../../../../etc/passwd", "%2e%2e%2f", "' OR 1=1--",
        "\u{0}", "🔑", "\u{202E}gnp.exe", "a\nb",
    ]

    static let registeredClaims = ["iss", "sub", "aud", "exp", "nbf", "iat", "jti"]

    /// A header built from real parameter names, mixing plausible values with
    /// malformed ones and degenerate structures.
    mutating func directedHeaderJSON() -> String {
        var pairs: [String] = []

        pairs.append("\"alg\":\"\(Self.algorithmValues[Int(nextUInt(UInt64(Self.algorithmValues.count)))])\"")

        if nextBool() {
            pairs.append("\"kid\":\(jsonEscaped(Self.kidValues[Int(nextUInt(UInt64(Self.kidValues.count)))]))")
        }

        if nextBool() { pairs.append("\"crit\":\(heterogeneousArray())") }
        if nextBool() { pairs.append("\"x5c\":\(heterogeneousArray())") }
        if nextBool() { pairs.append("\"jwk\":\(jsonValue(depth: 2))") }

        let extras = Int(nextUInt(3))
        for _ in 0..<extras {
            let name = Self.registeredHeaderParameters[
                Int(nextUInt(UInt64(Self.registeredHeaderParameters.count)))]
            let value = nextUInt(4) == 0 ? degenerateValue() : jsonValue(depth: Int(nextUInt(3)))
            pairs.append("\"\(name)\":\(value)")
        }

        return "{\(pairs.joined(separator: ","))}"
    }

    /// An array whose elements deliberately are not all the same type — the shape
    /// the `crit`/`x5c` accessors silently filter rather than reject.
    mutating func heterogeneousArray() -> String {
        let count = Int(nextUInt(5))
        let elements = (0..<count).map { _ -> String in
            switch nextUInt(6) {
            case 0: return jsonString()
            case 1: return jsonNumber()
            case 2: return "null"
            case 3: return "true"
            case 4: return "[]"
            default: return "{}"
            }
        }
        return "[\(elements.joined(separator: ","))]"
    }

    /// A payload built from registered claim names with deliberately wrong types,
    /// reaching `JWTUnixEpochClaim` (`Date` decoding) and `JWTMultiValueClaim`.
    mutating func claimsPayloadJSON() -> String {
        var pairs: [String] = []
        for claim in Self.registeredClaims where nextBool() {
            pairs.append("\"\(claim)\":\(claimValue(for: claim))")
        }
        return "{\(pairs.joined(separator: ","))}"
    }

    private mutating func claimValue(for claim: String) -> String {
        let value: String
        switch nextUInt(8) {
        case 0: value = jsonNumber()  // huge/negative epochs for exp/nbf/iat
        case 1: value = jsonString()
        case 2: value = "null"
        case 3: value = "true"
        case 4: value = multiValueArray()
        case 5: value = "{}"
        case 6: value = degenerateValue()
        default:
            // Plausible values, so most tokens are well-formed enough to get deep.
            value = ["exp", "nbf", "iat"].contains(claim) ? "2000000000" : jsonString()
        }
        return value
    }

    private mutating func multiValueArray() -> String {
        let count = Int(nextUInt(5))
        return "[" + (0..<count).map { _ in jsonString() }.joined(separator: ",") + "]"
    }

    mutating func jwksJSON() -> String {
        let count = Int(nextUInt(4))
        let keys = (0..<count).map { _ in jwkJSON() }
        switch nextUInt(8) {
        case 0: return "{\"keys\":\(degenerateValue())}"
        case 1: return "{}"
        case 2: return "[\(keys.joined(separator: ","))]"  // array instead of object
        default: return "{\"keys\":[\(keys.joined(separator: ","))]}"
        }
    }

    mutating func jwkJSON() -> String {
        let members = ["kty", "use", "key_ops", "alg", "kid", "crv", "x", "y", "n", "e", "d", "p", "q"]
        var pairs: [String] = []
        for member in members where nextUInt(3) == 0 {
            switch nextUInt(5) {
            case 0: pairs.append("\"\(member)\":\(jsonNumber())")
            case 1: pairs.append("\"\(member)\":\(jsonValue(depth: 2))")
            case 2: pairs.append("\"\(member)\":\(jsonString())")
            case 3: pairs.append("\"\(member)\":\"\(corruptedBase64URL())\"")
            default: pairs.append("\"\(member)\":\(degenerateValue())")
            }
        }
        if nextBool() { pairs.append("\"kty\":\"\(["RSA", "EC", "oct", "OKP", "", "rsa"][Int(nextUInt(6))])\"") }
        return "{\(pairs.joined(separator: ","))}"
    }

    mutating func corruptedBase64URL() -> String {
        let alphabet = Array("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")
        switch nextUInt(8) {
        case 0:
            let length = 1 + 4 * Int(nextUInt(16))
            return String((0..<length).map { _ in alphabet[Int(nextUInt(64))] })
        case 1:
            let length = Int(nextUInt(64))
            return String((0..<length).map { _ in alphabet[Int(nextUInt(64))] })
        case 2: return "===="  // padding only
        case 3: return "AB=CD"  // padding in the middle
        case 4: return "++//"  // standard-base64 alphabet, not URL-safe
        case 5: return "AAAA===="  // over-padded
        case 6: return "🔑🔑🔑"  // non-ASCII
        default: return String(repeating: "A", count: logUniformSize(upTo: 8_192))
        }
    }

    func jsonEscaped(_ value: String) -> String {
        var out = "\""
        for scalar in value.unicodeScalars {
            switch scalar {
            case "\"": out += "\\\""
            case "\\": out += "\\\\"
            case "\n": out += "\\n"
            case "\r": out += "\\r"
            case "\t": out += "\\t"
            default:
                if scalar.value < 0x20 {
                    out += String(format: "\\u%04x", scalar.value)
                } else {
                    out.unicodeScalars.append(scalar)
                }
            }
        }
        return out + "\""
    }
}
