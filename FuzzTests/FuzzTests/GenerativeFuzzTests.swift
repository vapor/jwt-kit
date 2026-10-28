import Foundation
import JWTKit
import Testing

func iterations(_ fallback: Int) -> Int {
    let environment = ProcessInfo.processInfo.environment
    if let raw = environment["JWT_FUZZ_ITERATIONS"], let value = Int(raw), value > 0 {
        return value
    }
    if let raw = environment["JWT_FUZZ_SCALE"], let scale = Int(raw), scale > 0 {
        return fallback * scale
    }
    return fallback
}

/// A permissive payload to focus on parsing and verification
struct FuzzPayload: JWTPayload, Equatable {
    var sub: String?
    var exp: Int?
    var name: String?
    var admin: Bool?

    func verify(using _: some JWTAlgorithm) throws {}
}

private func fuzzKeys() async -> JWTKeyCollection {
    await JWTKeyCollection().add(hmac: "fuzz-secret", digestAlgorithm: .sha256)
}

/// These are mainly to test that the library doesn't crash
@Suite("Generative fuzzing")
struct GenerativeFuzzTests {

    // MARK: - Valid input

    @Test("Signed tokens with random headers round-trip")
    func signedTokensRoundTrip() async throws {
        var generator = JWTFuzzGenerator(seed: 0x11F7_2A3B_4C5D_6E7F)
        let keys = await fuzzKeys()

        for _ in 0..<iterations(400) {
            var fields: [String: JWTHeaderField] = [:]
            for index in 0..<Int(generator.nextUInt(5)) {
                fields["custom\(index)"] = generator.roundTrippableField(depth: 2)
            }
            let payload = FuzzPayload(
                sub: "1234567890", exp: 2_000_000_000, name: "vapor", admin: true)

            let token = try await keys.sign(payload, header: JWTHeader(fields: fields))
            let verified = try await keys.verify(token, as: FuzzPayload.self)
            #expect(verified == payload)
        }
    }

    @Test("Header fields survive a JSON round trip")
    func headerFieldRoundTrip() throws {
        var generator = JWTFuzzGenerator(seed: 0x2C4E_6A8B_0D1F_3E5A)
        let encoder = JSONEncoder()
        let decoder = JSONDecoder()

        for _ in 0..<iterations(2_000) {
            var fields: [String: JWTHeaderField] = [:]
            for index in 0..<Int(generator.nextUInt(6)) {
                fields["f\(index)"] = generator.roundTrippableField(depth: 3)
            }
            let header = JWTHeader(fields: fields)
            let decoded = try decoder.decode(JWTHeader.self, from: encoder.encode(header))
            #expect(decoded.fields == header.fields)
        }
    }

    // MARK: - Malformed input

    @Test("Generated headers never crash the parser")
    func generatedHeadersNeverCrash() async throws {
        var generator = JWTFuzzGenerator(seed: 0x5EED_C0FF_EE12_3456)
        let keys = await fuzzKeys()

        for index in 0..<iterations(3_000) {
            let header = generator.headerJSON(validAlg: index.isMultiple(of: 2))
            let payload = generator.payloadJSON()
            let token = generator.token(header: header, payload: payload)
            _ = try? await keys.verify(token, as: FuzzPayload.self)
            _ = try? await keys.unverified(token, as: FuzzPayload.self)
        }
        #expect(Bool(true))  // reaching this line means nothing trapped
    }

    @Test("Mutated tokens never crash the parser")
    func mutatedTokensNeverCrash() async throws {
        var generator = JWTFuzzGenerator(seed: 0xBEEF_5678_1234_DEAD)
        let keys = await fuzzKeys()

        for _ in 0..<iterations(3_000) {
            var token = generator.token(
                header: generator.headerJSON(), payload: generator.payloadJSON())
            generator.mutate(&token)
            _ = try? await keys.verify(token, as: FuzzPayload.self)
            _ = try? await keys.unverified(token, as: FuzzPayload.self)
        }
        #expect(Bool(true))
    }

    @Test("Random bytes never crash the parser")
    func randomBytesNeverCrash() async throws {
        var generator = JWTFuzzGenerator(seed: 0x1357_9BDF_2468_ACE0)
        let keys = await fuzzKeys()

        for _ in 0..<iterations(3_000) {
            let bytes = generator.randomBytes(maxLength: 256)
            _ = try? await keys.verify(bytes, as: FuzzPayload.self)
            _ = try? await keys.unverified(bytes, as: FuzzPayload.self)
        }
        #expect(Bool(true))
    }

    @Test("Well-formed envelopes with garbage segments never crash the parser")
    func garbageSegmentsNeverCrash() async throws {
        var generator = JWTFuzzGenerator(seed: 0x0F1E_2D3C_4B5A_6978)
        let keys = await fuzzKeys()

        for _ in 0..<iterations(3_000) {
            let header = JWTFuzzGenerator.base64URL(generator.randomBytes(maxLength: 128))
            let payload = JWTFuzzGenerator.base64URL(generator.randomBytes(maxLength: 128))
            let signature = JWTFuzzGenerator.base64URL(generator.randomBytes(maxLength: 64))
            let token = Array("\(header).\(payload).\(signature)".utf8)
            _ = try? await keys.verify(token, as: FuzzPayload.self)
            _ = try? await keys.unverified(token, as: FuzzPayload.self)
        }
        #expect(Bool(true))
    }

    @Test(
        "Deep fuzzing pass",
        .enabled(if: ProcessInfo.processInfo.environment["JWT_FUZZ_DEEP"] != nil)
    )
    func deepPass() async throws {
        var generator = JWTFuzzGenerator(seed: 0xDEE9_0F22_1234_5678)
        let keys = await fuzzKeys()

        for index in 0..<iterations(100_000) {
            let header = generator.headerJSON(validAlg: index.isMultiple(of: 2))
            var token = generator.token(header: header, payload: generator.payloadJSON())
            _ = try? await keys.verify(token, as: FuzzPayload.self)

            generator.mutate(&token)
            _ = try? await keys.verify(token, as: FuzzPayload.self)
            _ = try? await keys.unverified(token, as: FuzzPayload.self)

            let garbage = generator.randomBytes(maxLength: 512)
            _ = try? await keys.verify(garbage, as: FuzzPayload.self)
        }
        #expect(Bool(true))
    }
}
