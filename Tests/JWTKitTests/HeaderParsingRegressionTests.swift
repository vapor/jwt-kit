import Testing
import JWTKit
import Foundation

@Suite("Header parsing regressions")
struct HeaderParsingRegressionTests {

    struct RegressionPayload: JWTPayload {
        var sub: String?
        func verify(using _: some JWTAlgorithm) throws {}
    }

    static let parser = DefaultJWTParser()

    static func keys() async -> JWTKeyCollection {
        await JWTKeyCollection().add(hmac: "a-string-secret-at-least-256-bits-long", digestAlgorithm: .sha256)
    }

    /// Helper to build tokens with dodgy headers to test for crashes when decoding untrusted tokens
    static func token(header json: String) -> String {
        "\(base64URL(json)).\(base64URL(#"{"sub":"1234567890"}"#)).AAAA"
    }

    static func parseHeader(_ json: String) throws -> JWTHeader {
        try parser.parse(Array(token(header: json).utf8), as: RegressionPayload.self).header
    }

    static func base64URL(_ string: String) -> String { base64URL(Array(string.utf8)) }

    static func base64URL(_ bytes: [UInt8]) -> String {
        Data(bytes).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }

    @Test("GHSA-hfm2-66rr-3mcf header value doesn't crash", .bug("https://github.com/vapor/jwt-kit/security/advisories/GHSA-hfm2-66rr-3mcf"))
    func advisoryProofOfConcept() async throws {
        let keys = await Self.keys()
        let token = "eyJhbGciOiJIUzI1NiIsIngiOjFlMzAwfQ.eyJzdWIiOiIxMjMifQ.invalid"
        // The signature is the literal string `invalid`, so reaching
        // `signatureVerificationFailed` is what proves the header parsed rather than trapped.
        let error = await #expect(throws: JWTError.self) {
            _ = try await keys.verify(token, as: RegressionPayload.self)
        }
        #expect(error?.errorType == .signatureVerificationFailed)
    }

    @Test(
        "Representable numeric header boundaries parse",
        .bug("https://github.com/vapor/jwt-kit/security/advisories/GHSA-hfm2-66rr-3mcf"),
        arguments: [
            "1e300", "-1e300", "1e308", "-1e308",
            // Plain-literal Int overflow — no exponent involved
            "9223372036854775807",  // Int.max
            "9223372036854775808",  // Int.max + 1
            "9223372036854775809",
            "-9223372036854775808",  // Int.min
            "-9223372036854775809",  // Int.min - 1
            "18446744073709551615",  // UInt64.max
            "18446744073709551616",
            // Double precision cliff
            "9007199254740992",  // 2^53
            "9007199254740993",  // 2^53 + 1
            "-9007199254740993",
            "1.7976931348623157e308",  // Double.greatestFiniteMagnitude
            "5e-324",  // Double.leastNonzeroMagnitude
        ]
    )
    func representableNumericBoundariesParse(_ value: String) {
        #expect(throws: Never.self) {
            _ = try Self.parseHeader(#"{"alg":"HS256","x":\#(value)}"#)
        }
    }

    @Test(
        "Unrepresentable numeric header boundaries are malformed",
        .bug("https://github.com/vapor/jwt-kit/security/advisories/GHSA-hfm2-66rr-3mcf"),
        arguments: [
            "1e309", "-1e309", "1e400", "-1e400", "1e-400",
            "1.7976931348623159e308",  // just past greatestFiniteMagnitude
            String(repeating: "9", count: 400),
            "-" + String(repeating: "9", count: 400),
            "0." + String(repeating: "0", count: 400) + "1",
            // Not valid JSON numbers
            "01", "+1", ".5", "5.", "1e", "1e+", "--1", "1.2.3", "0x10",
            "Infinity", "-Infinity", "NaN", "1e999999999999999999",
        ]
    )
    func unrepresentableNumericBoundariesAreMalformed(_ value: String) {
        let error = #expect(throws: JWTError.self) {
            _ = try Self.parseHeader(#"{"alg":"HS256","x":\#(value)}"#)
        }
        #expect(error?.errorType == .malformedToken)
    }

    @Test(
        "Nested numeric boundaries behave as at the top level",
        .bug("https://github.com/vapor/jwt-kit/security/advisories/GHSA-hfm2-66rr-3mcf"),
        arguments: [
            ("1e300", true),
            ("9223372036854775808", true),
            ("-9223372036854775809", true),
            ("1e400", false),
        ]
    )
    func nestedNumericBoundaries(_ value: String, _ isValid: Bool) throws {
        for shape in [#"[\#(value)]"#, #"{"y":\#(value)}"#, #"[[{"y":[\#(value)]}]]"#] {
            let header = #"{"alg":"HS256","x":\#(shape)}"#
            if isValid {
                #expect(throws: Never.self) { _ = try Self.parseHeader(header) }
            } else {
                let error = #expect(throws: JWTError.self) { _ = try Self.parseHeader(header) }
                #expect(error?.errorType == .malformedToken)
            }
        }
    }

    @Test("Nesting within limit parses normally", .bug("https://github.com/vapor/jwt-kit/security/advisories/GHSA-jhmq-wqhf-47x2"), arguments: NestedJSONShape.allCases)
    func shallowNestingIsFine(_ style: NestedJSONShape) {
        #expect(throws: Never.self) {
            _ = try Self.parseHeader(#"{"alg":"HS256","x":\#(style.json(depth: 8))}"#)
        }
    }

    @Test("Depth limit works correctly", .bug("https://github.com/vapor/jwt-kit/security/advisories/GHSA-jhmq-wqhf-47x2"), arguments: NestedJSONShape.allCases)
    func depthLimitBrackets(_ style: NestedJSONShape) {
        #expect(throws: Never.self) {
            _ = try Self.parseHeader(#"{"alg":"HS256","x":\#(style.json(depth: 25))}"#)
        }

        let rejected = #expect(throws: JWTError.self) {
            _ = try Self.parseHeader(#"{"alg":"HS256","x":\#(style.json(depth: 40))}"#)
        }
        #expect(rejected?.errorType == .malformedToken)
    }

    @Test("Depth guard cuts off at maximumDepth", .bug("https://github.com/vapor/jwt-kit/security/advisories/GHSA-jhmq-wqhf-47x2"))
    func depthLimitBoundary() throws {
        func arrays(_ depth: Int) -> Data {
            Data((String(repeating: "[", count: depth) + String(repeating: "]", count: depth)).utf8)
        }
        func objects(_ depth: Int) -> Data {
            Data((String(repeating: #"{"a":"#, count: depth) + "0" + String(repeating: "}", count: depth)).utf8)
        }
        let decoder = JSONDecoder()

        #expect(throws: Never.self) { try decoder.decode(JWTHeaderField.self, from: arrays(33)) }
        #expect(throws: DecodingError.self) { try decoder.decode(JWTHeaderField.self, from: arrays(34)) }

        #expect(throws: Never.self) { try decoder.decode(JWTHeaderField.self, from: objects(32)) }
        #expect(throws: DecodingError.self) { try decoder.decode(JWTHeaderField.self, from: objects(33)) }
    }

    @Test(
        "Deep nesting is bounded rather than overflowing the stack",
        .bug("https://github.com/vapor/jwt-kit/security/advisories/GHSA-jhmq-wqhf-47x2"),
        arguments: NestedJSONShape.allCases
    )
    func deepNestingIsBounded(_ style: NestedJSONShape) {
        for depth in [200, 300, 500] {
            let error = #expect(throws: JWTError.self) {
                _ = try Self.parseHeader(#"{"alg":"HS256","x":\#(style.json(depth: depth))}"#)
            }
            #expect(error?.errorType == .malformedToken)
        }
    }

    @Test(
        "Nesting with Foundation's limit", 
        .bug("https://github.com/vapor/jwt-kit/security/advisories/GHSA-jhmq-wqhf-47x2"),
        arguments: NestedJSONShape.allCases
    )
    func veryDeepNestingIsRejected(_ style: NestedJSONShape) {
        let error = #expect(throws: JWTError.self) {
            _ = try Self.parseHeader(#"{"alg":"HS256","x":\#(style.json(depth: 600))}"#)
        }
        #expect(error?.errorType == .malformedToken)
    }

    @Test(
        "Malformed token envelopes are rejected before signing",
        .bug("https://github.com/vapor/jwt-kit/security/advisories/GHSA-jhmq-wqhf-47x2"),
        arguments: [
            "", ".", "..", "...", "a", "a.b", "a.b.c.d", "....",
            "!!!.!!!.!!!",  // outside the base64url alphabet
            ".eyJzdWIiOiIxIn0.",  // empty header
            "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0",  // two parts only
            "e.e.e",
            "_-_-.-_-_._-_-",
        ]
    )
    func malformedEnvelopesThrow(_ token: String) async throws {
        let keys = await Self.keys()
        let error = await #expect(throws: JWTError.self) {
            _ = try await keys.verify(token, as: RegressionPayload.self)
        }
        #expect(error?.errorType == .malformedToken)
    }

    @Test("An empty signature fails verification rather than parsing")
    func emptySignatureFailsVerification() async throws {
        let keys = await Self.keys()
        let error = await #expect(throws: JWTError.self) {
            _ = try await keys.verify("eyJhbGciOiJIUzI1NiJ9..", as: RegressionPayload.self)
        }
        #expect(error?.errorType == .signatureVerificationFailed)
    }

    @Test("Non-UTF-8 segments are rejected at the point they are read")
    func nonUTF8SegmentsThrow() async throws {
        let keys = await Self.keys()
        let invalid = Self.base64URL([0xFF, 0xFE, 0xFD, 0xC0, 0x80])

        let badHeader = await #expect(throws: JWTError.self) {
            _ = try await keys.verify("\(invalid).\(invalid).AAAA", as: RegressionPayload.self)
        }
        #expect(badHeader?.errorType == .malformedToken)

        let badPayload = await #expect(throws: JWTError.self) {
            _ = try await keys.verify("eyJhbGciOiJIUzI1NiJ9.\(invalid).AAAA", as: RegressionPayload.self)
        }
        #expect(badPayload?.errorType == .signatureVerificationFailed)

        let unverified = #expect(throws: JWTError.self) {
            _ = try Self.parser.parse(
                Array("eyJhbGciOiJIUzI1NiJ9.\(invalid).AAAA".utf8), as: RegressionPayload.self)
        }
        #expect(unverified?.errorType == .malformedToken)
    }

    @Test(
        "Malformed header JSON is rejected",
        arguments: [
            "", "null", "true", "[]", "[1,2,3]", #""string""#, "0", "{",
            #"{"alg":}"#, #"{"alg""#, #"{"alg":"HS256""#,
            #"{"kid":1e400}"#,
            #"{"alg":"HS256","x":"\ud800"}"#,  // lone surrogate
        ]
    )
    func malformedHeaderJSONThrows(_ json: String) {
        let error = #expect(throws: JWTError.self) {
            _ = try Self.parseHeader(json)
        }
        #expect(error?.errorType == .malformedToken)
    }

    @Test(
        "Algorithm field types have stable verification outcomes",
        arguments: [
            (#"{"alg":123}"#, JWTError.ErrorType.malformedToken),
            (#"{"alg":[]}"#, .malformedToken),
            (#"{"alg":{}}"#, .malformedToken),
            (#"{"alg":null}"#, .signatureVerificationFailed),
            (#"{"alg":"HS256","alg":"none"}"#, .signatureVerificationFailed),  // duplicate key
        ]
    )
    func nonStringAlgReachesSignatureCheck(_ json: String, _ expected: JWTError.ErrorType) async throws {
        let keys = await Self.keys()
        let error = await #expect(throws: JWTError.self) {
            _ = try await keys.verify(Self.token(header: json), as: RegressionPayload.self)
        }
        #expect(error?.errorType == expected)
    }

    struct AudiencePayload: JWTPayload {
        var aud: AudienceClaim?
        func verify(using _: some JWTAlgorithm) throws {}
    }

    @Test("Empty multi-value claims decode rather than crashing", .bug("https://github.com/vapor/jwt-kit/security/advisories/GHSA-jhmq-wqhf-47x2"))
    func emptyMultiValueClaimDecodes() async throws {
        let keys = await Self.keys()
        let token = "\(Self.base64URL(#"{"alg":"HS256"}"#)).\(Self.base64URL(#"{"aud":[]}"#)).AAAA"

        let payload = try await keys.unverified(token, as: AudiencePayload.self)
        #expect(payload.aud?.value == [])

        // Reaches signature verification, so decoding the empty claim didn't fail.
        let error = await #expect(throws: JWTError.self) {
            _ = try await keys.verify(token, as: AudiencePayload.self)
        }
        #expect(error?.errorType == .signatureVerificationFailed)
    }

    @Test("An empty audience matches no audience")
    func emptyAudienceMatchesNothing() throws {
        #expect(throws: JWTError.self) {
            try AudienceClaim(value: []).verifyIntendedAudience(includes: "vapor")
        }
        #expect(throws: Never.self) {
            try AudienceClaim(value: ["vapor"]).verifyIntendedAudience(includes: "vapor")
        }
    }

    @Test("Scalar and array audiences still decode")
    func audienceFormsStillDecode() throws {
        let scalar = "\(Self.base64URL(#"{"alg":"HS256"}"#)).\(Self.base64URL(#"{"aud":"a"}"#)).AAAA"
        let array = "\(Self.base64URL(#"{"alg":"HS256"}"#)).\(Self.base64URL(#"{"aud":["a","b"]}"#)).AAAA"
        #expect(try Self.parser.parse(Array(scalar.utf8), as: AudiencePayload.self).payload.aud?.value == ["a"])
        #expect(try Self.parser.parse(Array(array.utf8), as: AudiencePayload.self).payload.aud?.value == ["a", "b"])
    }

    @Test(
        "Decoded dates re-encode without trapping",
        .bug("https://github.com/vapor/jwt-kit/security/advisories/GHSA-jhmq-wqhf-47x2"),
        arguments: ["1e300", "-1e300", "1e308", "-1e308", "9223372036854775808", "1.5e300"],
    )
    func extremeDatesReEncode(_ epoch: String) async throws {
        struct ExpiryPayload: JWTPayload {
            var exp: ExpirationClaim?
            func verify(using _: some JWTAlgorithm) throws {}
        }

        let token = "\(Self.base64URL(#"{"alg":"HS256"}"#)).\(Self.base64URL(#"{"exp":\#(epoch)}"#)).AAAA"
        let parsed = try Self.parser.parse(Array(token.utf8), as: ExpiryPayload.self)

        let integerEncoder = JSONEncoder()
        integerEncoder.dateEncodingStrategy = .integerSecondsSince1970
        #expect(throws: EncodingError.self) {
            try integerEncoder.encode(parsed.payload)
        }

        let doubleEncoder = JSONEncoder()
        doubleEncoder.dateEncodingStrategy = .secondsSince1970
        #expect(throws: Never.self) { try doubleEncoder.encode(parsed.payload) }
    }

    @Test("Epochs that round into range encode at the rounded value")
    func epochsThatRoundIntoRangeEncode() throws {
        struct ExpiryPayload: JWTPayload {
            var exp: ExpirationClaim?
            func verify(using _: some JWTAlgorithm) throws {}
        }

        let token = "\(Self.base64URL(#"{"alg":"HS256"}"#)).\(Self.base64URL(#"{"exp":-9223372036854775809}"#)).AAAA"
        let parsed = try Self.parser.parse(Array(token.utf8), as: ExpiryPayload.self)

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .integerSecondsSince1970
        let encoded = try encoder.encode(parsed.payload)
        #expect(String(decoding: encoded, as: UTF8.self).contains(String(Int.min)))
    }

    @Test("Ordinary dates round-trip through the integer strategy", arguments: [0, 1, 2_000_000_000, -1_000])
    func ordinaryDatesRoundTrip(_ epoch: Int) throws {
        struct ExpiryPayload: JWTPayload, Equatable {
            var exp: ExpirationClaim
            func verify(using _: some JWTAlgorithm) throws {}
        }

        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .integerSecondsSince1970
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .integerSecondsSince1970

        let payload = ExpiryPayload(exp: .init(value: Date(timeIntervalSince1970: Double(epoch))))
        let decoded = try decoder.decode(ExpiryPayload.self, from: encoder.encode(payload))
        #expect(decoded == payload)
    }

    @Test("Integers beyond 2^53 lose precision through the Double-based decoder")
    func largeIntegersLosePrecision() throws {
        let header = JWTHeader(fields: ["x": .int(9_007_199_254_740_993)])  // 2^53 + 1
        let decoded = try JSONDecoder().decode(JWTHeader.self, from: JSONEncoder().encode(header))
        #expect(decoded.fields["x"] != .int(9_007_199_254_740_993))
        #expect(decoded.fields["x"] == .int(9_007_199_254_740_992))
    }

    @Test("Decimals re-decode as integers")
    func integralDecimalsBecomeIntegers() throws {
        let header = JWTHeader(fields: ["x": .decimal(2.0)])
        let decoded = try JSONDecoder().decode(JWTHeader.self, from: JSONEncoder().encode(header))
        #expect(decoded.fields["x"] == .int(2))
    }

    @Test("Encoding non-finite header values throws", arguments: [Double.infinity, -.infinity, .nan])
    func nonFiniteEncodingThrows(_ value: Double) throws {
        #expect(throws: EncodingError.self) {
            try JSONEncoder().encode(JWTHeader(fields: ["x": .decimal(value)]))
        }
    }
}

enum NestedJSONShape: CaseIterable, Sendable {
    case arrays, objects, mixed

    func json(depth: Int) -> String {
        switch self {
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

}
