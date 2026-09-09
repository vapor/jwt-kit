// Isolated timing tests for the individual stages of signing and verifying a JWT.
//
// Each test times one operation in a tight loop and prints microseconds and, where useful,
// a comparison against the raw SwiftCrypto call or a plain Codable struct. They pass as long as
// the operation works, so they double as smoke tests; the numbers are what you're after.
//
// Run from the command line (release, serialized, so timings are meaningful):
//
//     swift test -c release -Xswiftc -enable-testing --no-parallel --filter Performance
//
// Run in Xcode: pick a test in the navigator and use Product > Perform Action > Profile to open
// it in Instruments (Time Profiler has the flame graph). Note that Xcode builds the test target
// in Debug, which inflates JWTKit's own code relative to Foundation and SwiftCrypto, so use the
// shape of the graph rather than the absolute split.
//
// Set JWTKIT_PERF_ITERATIONS in the environment (or the scheme) to run longer for profiling.

#if canImport(Testing)
import Crypto
import CryptoExtras
import Testing

@testable import JWTKit

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

@Suite("Performance", .serialized)
struct PerformanceTests {
    static let iterations = Int(ProcessInfo.processInfo.environment["JWTKIT_PERF_ITERATIONS"] ?? "") ?? 2_000

    // MARK: Fixtures

    /// A three-field header (alg, typ, kid), which is what most real tokens carry.
    let header = JWTHeader(fields: ["alg": "HS256", "typ": "JWT", "kid": "key-1"])
    let payload = TestPayload(sub: "vapor", name: "Foo", admin: false, exp: .init(value: .distantFuture))
    let hmacSecret = "a-very-long-secret-key-of-at-least-32-bytes!!"
    let encoder: JSONEncoder = {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .secondsSince1970
        return encoder
    }()
    let decoder: JSONDecoder = {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .secondsSince1970
        return decoder
    }()

    struct PlainHeader: Codable {
        var alg: String
        var typ: String
        var kid: String?
    }

    func hmacCollection() async -> JWTKeyCollection {
        await JWTKeyCollection().add(hmac: HMACKey(from: hmacSecret), digestAlgorithm: .sha256, kid: "key-1")
    }

    func hmacToken() async throws -> String {
        try await hmacCollection().sign(payload, kid: "key-1")
    }

    // MARK: Parsing (everything in `verify` that is not cryptography)

    @Test("Parse: split token into parts")
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *)
    func parseSplit() async throws {
        let token = try await hmacToken().bytes
        try measure("getTokenParts (split + copy)") { _ = try DefaultJWTParser().getTokenParts(token) }
    }

    @Test("Parse: JSON decode header, JWTHeader vs plain struct")
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *)
    func headerDecode() throws {
        let json = try encoder.encode(header)
        try measure("JSONDecoder JWTHeader (3 string fields)") { _ = try decoder.decode(JWTHeader.self, from: json) }
        try measure("JSONDecoder plain struct, same JSON") { _ = try decoder.decode(PlainHeader.self, from: json) }
        try measure("JSONDecoder [String: JWTHeaderField]") { _ = try decoder.decode([String: JWTHeaderField].self, from: json) }
    }

    @Test("Parse: JSON decode payload")
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *)
    func payloadDecode() throws {
        let json = try encoder.encode(payload)
        try measure("JSONDecoder TestPayload (4 fields)") { _ = try decoder.decode(TestPayload.self, from: json) }
    }

    @Test("Parse: header is decoded by parseHeader and again by parse")
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *)
    func headerDecodedTwice() async throws {
        let token = try await hmacToken().bytes
        let parser = DefaultJWTParser()
        try measure("parseHeader (split + b64 + decode header)") { _ = try parser.parseHeader(token) }
        try measure("parse (split + b64 x3 + utf8 x2 + decode both)") { _ = try parser.parse(token, as: TestPayload.self) }
    }

    @Test("Parse: unverified vs verify HS256")
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *)
    func parseVersusVerify() async throws {
        let collection = await hmacCollection()
        let token = try await hmacToken()
        try await measure("unverified (parse only)") { _ = try await collection.unverified(token, as: TestPayload.self) }
        try await measure("verify HS256 (full path)") { _ = try await collection.verify(token, as: TestPayload.self) }
        try await measure("verify HS256 with [UInt8] input") { _ = try await collection.verify(token.bytes, as: TestPayload.self) }
    }

    // MARK: Serializing (everything in `sign` that is not cryptography)

    @Test("Serialize: JSON encode header, JWTHeader vs plain struct")
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *)
    func headerEncode() throws {
        let plain = PlainHeader(alg: "HS256", typ: "JWT", kid: "key-1")
        try measure("JSONEncoder JWTHeader (3 string fields)") { _ = try encoder.encode(header) }
        try measure("JSONEncoder plain struct, same JSON") { _ = try encoder.encode(plain) }
    }

    @Test("Serialize: JSON encode payload")
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *)
    func payloadEncode() throws {
        try measure("JSONEncoder TestPayload (4 fields)") { _ = try encoder.encode(payload) }
    }

    @Test("Serialize: sign HS256")
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *)
    func signHS256() async throws {
        let collection = await hmacCollection()
        try await measure("sign HS256 (default header)") { _ = try await collection.sign(payload) }
        try await measure("sign HS256 (custom header)") { _ = try await collection.sign(payload, header: ["kid": "key-1", "cty": "JWT"]) }
    }

    // MARK: Crypto (raw SwiftCrypto call next to the JWTKit call that wraps it)

    @Test("Crypto: HS256 raw vs JWTKit")
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *)
    func hs256() async throws {
        let key = SymmetricKey(data: hmacSecret.bytes)
        let collection = await hmacCollection()
        let token = try await hmacToken()
        let input = Array(token.bytes.prefix { $0 != 0x2E } + [0x2E]) + Array(token.split(separator: ".")[1].utf8)
        let mac = HMAC<SHA256>.authenticationCode(for: input, using: key)
        measure("raw HMAC.authenticationCode") { _ = HMAC<SHA256>.authenticationCode(for: input, using: key) }
        measure("raw HMAC.isValidAuthenticationCode") { _ = HMAC<SHA256>.isValidAuthenticationCode(mac, authenticating: input, using: key) }
        try await measure("JWTKit sign HS256") { _ = try await collection.sign(payload) }
        try await measure("JWTKit verify HS256") { _ = try await collection.verify(token, as: TestPayload.self) }
    }

    @Test("Crypto: ES256 raw vs JWTKit")
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *)
    func es256() async throws {
        let key = P256.Signing.PrivateKey()
        let digest = SHA256.hash(data: hmacSecret.bytes)
        let signature = try key.signature(for: digest)
        let collection = try await JWTKeyCollection().add(ecdsa: ES256PrivateKey(backing: key))
        let token = try await collection.sign(payload)
        try measure("raw P256 sign", scale: 4) { _ = try key.signature(for: digest) }
        measure("raw P256 verify", scale: 4) { _ = key.publicKey.isValidSignature(signature, for: digest) }
        try await measure("JWTKit sign ES256", scale: 4) { _ = try await collection.sign(payload) }
        try await measure("JWTKit verify ES256", scale: 4) { _ = try await collection.verify(token, as: TestPayload.self) }
    }

    @Test("Crypto: EdDSA raw vs JWTKit")
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *)
    func eddsa() async throws {
        let key = Curve25519.Signing.PrivateKey()
        let input = hmacSecret.bytes
        let signature = try key.signature(for: input)
        let collection = await JWTKeyCollection().add(eddsa: EdDSA.PrivateKey(backing: key))
        let token = try await collection.sign(payload)
        try measure("raw Ed25519 sign", scale: 4) { _ = try key.signature(for: input) }
        measure("raw Ed25519 verify", scale: 4) { _ = key.publicKey.isValidSignature(signature, for: input) }
        try await measure("JWTKit sign EdDSA", scale: 4) { _ = try await collection.sign(payload) }
        try await measure("JWTKit verify EdDSA", scale: 4) { _ = try await collection.verify(token, as: TestPayload.self) }
    }

    @Test("Crypto: RS256 raw vs JWTKit")
    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *)
    func rs256() async throws {
        let key = try _RSA.Signing.PrivateKey(pemRepresentation: privateKey)
        let digest = SHA256.hash(data: hmacSecret.bytes)
        let signature = try key.signature(for: digest, padding: .insecurePKCS1v1_5)
        let collection = try await JWTKeyCollection().add(rsa: Insecure.RSA.PrivateKey(backing: key), digestAlgorithm: .sha256)
        let token = try await collection.sign(payload)
        try measure("raw RSA-2048 sign", scale: 40) { _ = try key.signature(for: digest, padding: .insecurePKCS1v1_5) }
        measure("raw RSA-2048 verify", scale: 4) { _ = key.publicKey.isValidSignature(signature, for: digest, padding: .insecurePKCS1v1_5) }
        try await measure("JWTKit sign RS256", scale: 40) { _ = try await collection.sign(payload) }
        try await measure("JWTKit verify RS256", scale: 4) { _ = try await collection.verify(token, as: TestPayload.self) }
    }

    // MARK: Key collection lookup paths

    // @Test("Collection: RS256 key added directly vs loaded from JWKS")
    // @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, *)
    // func directVersusJWKS() async throws {
    //     let key = try Insecure.RSA.PrivateKey(pem: privateKey)
    //     let primitives = try key.publicKey.getKeyPrimitives()
    //     let jwks = """
    //         {"keys":[{"kty":"RSA","kid":"rsa-1","alg":"RS256","use":"sig",\
    //         "n":"\(String(decoding: primitives.modulus.base64URLEncodedBytes(), as: UTF8.self))",\
    //         "e":"\(String(decoding: primitives.publicExponent.base64URLEncodedBytes(), as: UTF8.self))"}]}
    //         """
    //     let signer = await JWTKeyCollection().add(rsa: key, digestAlgorithm: .sha256, kid: "rsa-1")
    //     let token = try await signer.sign(payload, kid: "rsa-1")
    //     let direct = await JWTKeyCollection().add(rsa: key.publicKey, digestAlgorithm: .sha256, kid: "rsa-1")
    //     let fromJWKS = try await JWTKeyCollection().add(jwksJSON: jwks)
    //     try await measure("verify RS256, key added directly with kid", scale: 4) {
    //         _ = try await direct.verify(token, as: TestPayload.self)
    //     }
    //     try await measure("verify RS256, key loaded from JWKS", scale: 4) { _ = try await fromJWKS.verify(token, as: TestPayload.self) }
    //     try await measure("add(jwksJSON:) one RSA key", scale: 4) { _ = try await JWTKeyCollection().add(jwksJSON: jwks) }
    // }
}

// MARK: - Timing helpers

/// Instructions retired by this process so far. Deterministic to well under 1% run to run, unlike
/// wall clock, so it is the number to compare between changes. Available on Darwin only.
func instructionsRetired() -> UInt64 {
    #if canImport(Darwin)
    var info = rusage_info_v4()
    // `proc_pid_rusage` takes the struct's address through a `rusage_info_t *` (a `void **`)
    // parameter, so the pointer has to be reinterpreted rather than passed by reference.
    let ok = unsafe withUnsafeMutablePointer(to: &info) { infoPointer -> Bool in
        unsafe infoPointer.withMemoryRebound(to: rusage_info_t?.self, capacity: 1) { rebound in
            unsafe proc_pid_rusage(getpid(), RUSAGE_INFO_V4, rebound) == 0
        }
    }
    return ok ? info.ri_instructions : 0
    #else
    return 0
    #endif
}

/// Runs `body` in a loop and prints the average time and instructions per call. `scale` divides
/// the iteration count for slow operations.
@discardableResult
func measure(_ name: String, scale: Int = 1, _ body: () throws -> Void) rethrows -> Duration {
    let iterations = max(PerformanceTests.iterations / scale, 10)
    for _ in 0..<max(iterations / 10, 5) { try body() }
    let clock = ContinuousClock()
    let instructionsBefore = instructionsRetired()
    let elapsed = try clock.measure {
        for _ in 0..<iterations { try body() }
    }
    let instructions = instructionsRetired() - instructionsBefore
    report(name, elapsed / iterations, instructions / UInt64(iterations))
    return elapsed / iterations
}

@discardableResult
func measure(_ name: String, scale: Int = 1, _ body: () async throws -> Void) async rethrows -> Duration {
    let iterations = max(PerformanceTests.iterations / scale, 10)
    for _ in 0..<max(iterations / 10, 5) { try await body() }
    let clock = ContinuousClock()
    let instructionsBefore = instructionsRetired()
    let start = clock.now
    for _ in 0..<iterations { try await body() }
    let elapsed = clock.now - start
    let instructions = instructionsRetired() - instructionsBefore
    report(name, elapsed / iterations, instructions / UInt64(iterations))
    return elapsed / iterations
}

private func report(_ name: String, _ perCall: Duration, _ instructions: UInt64) {
    let (seconds, attoseconds) = perCall.components
    let microseconds = Double(seconds) * 1_000_000 + Double(attoseconds) / 1e12
    let hundredths = Int((microseconds * 100).rounded())
    let fraction = hundredths % 100
    let formatted = "\(hundredths / 100).\(fraction < 10 ? "0" : "")\(fraction)"
    let paddedName = name + String(repeating: " ", count: max(0, 48 - name.count))
    let paddedValue = String(repeating: " ", count: max(0, 9 - formatted.count)) + formatted
    let instructionColumn = instructions == 0 ? "" : "   \(String(repeating: " ", count: max(0, 10 - String(instructions).count)))\(instructions) instr/op"
    print("  \(paddedName) \(paddedValue) µs/op\(instructionColumn)")
}
#endif  // canImport(Testing)
