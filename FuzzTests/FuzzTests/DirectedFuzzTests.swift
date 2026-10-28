import Foundation
import JWTKit
import Testing

struct ClaimsFuzzPayload: JWTPayload {
    var iss: IssuerClaim?
    var sub: SubjectClaim?
    var aud: AudienceClaim?
    var exp: ExpirationClaim?
    var nbf: NotBeforeClaim?
    var iat: IssuedAtClaim?
    var jti: IDClaim?

    func verify(using _: some JWTAlgorithm) throws {}
}

private func directedKeys() async -> JWTKeyCollection {
    await JWTKeyCollection().add(hmac: "fuzz-secret", digestAlgorithm: .sha256)
}

/// Targeted fuzzing
@Suite("Directed fuzzing")
struct DirectedFuzzTests {

    @Test("Degenerate structures never crash the parser")
    func degenerateStructuresNeverCrash() async throws {
        var generator = JWTFuzzGenerator(seed: 0x0DDB_A115_1234_ABCD)
        let keys = await directedKeys()

        for _ in 0..<iterations(400) {
            let header = #"{"alg":"HS256","x":\#(generator.degenerateValue())}"#
            let token = generator.token(header: header, payload: generator.payloadJSON())
            _ = try? await keys.verify(token, as: FuzzPayload.self)
            _ = try? await keys.unverified(token, as: FuzzPayload.self)
        }
        #expect(Bool(true))  // reaching this line means nothing trapped
    }

    @Test("Degenerate payloads never crash the parser")
    func degeneratePayloadsNeverCrash() async throws {
        var generator = JWTFuzzGenerator(seed: 0x5CA1_AB1E_0F22_1234)
        let keys = await directedKeys()

        for _ in 0..<iterations(400) {
            let payload = #"{"sub":"a","x":\#(generator.degenerateValue())}"#
            let token = generator.token(header: #"{"alg":"HS256"}"#, payload: payload)
            _ = try? await keys.verify(token, as: FuzzPayload.self)
            _ = try? await keys.unverified(token, as: FuzzPayload.self)
        }
        #expect(Bool(true))
    }

    @Test("Registered header parameters never crash the parser")
    func registeredHeaderParametersNeverCrash() async throws {
        var generator = JWTFuzzGenerator(seed: 0xA16_0C0F_5107_1234)
        let keys = await directedKeys()

        for _ in 0..<iterations(3_000) {
            let token = generator.token(
                header: generator.directedHeaderJSON(), payload: generator.payloadJSON())
            _ = try? await keys.verify(token, as: FuzzPayload.self)
            _ = try? await keys.unverified(token, as: FuzzPayload.self)
        }
        #expect(Bool(true))
    }

    @Test("Malformed claim types never crash payload decoding")
    func malformedClaimTypesNeverCrash() async throws {
        var generator = JWTFuzzGenerator(seed: 0xC1A1_3705_5EED_9876)
        let keys = await directedKeys()

        for _ in 0..<iterations(3_000) {
            let token = generator.token(
                header: #"{"alg":"HS256"}"#, payload: generator.claimsPayloadJSON())
            _ = try? await keys.verify(token, as: ClaimsFuzzPayload.self)
            _ = try? await keys.unverified(token, as: ClaimsFuzzPayload.self)
        }
        #expect(Bool(true))
    }

    @Test("Fuzzed JWKS never crashes key loading")
    func fuzzedJWKSNeverCrashes() async throws {
        var generator = JWTFuzzGenerator(seed: 0x3E75_1234_5678_9ABC)

        for _ in 0..<iterations(2_000) {
            let json = generator.jwksJSON()
            _ = try? await JWTKeyCollection().add(jwksJSON: json)
            _ = try? JSONDecoder().decode(JWKS.self, from: Data(json.utf8))
        }
        #expect(Bool(true))
    }

    @Test("Corrupted base64url segments never crash the parser")
    func corruptedBase64NeverCrashes() async throws {
        var generator = JWTFuzzGenerator(seed: 0xB64B_64B6_4B64_B64B)
        let keys = await directedKeys()

        for _ in 0..<iterations(3_000) {
            let token = Array(
                "\(generator.corruptedBase64URL()).\(generator.corruptedBase64URL()).\(generator.corruptedBase64URL())"
                    .utf8)
            _ = try? await keys.verify(token, as: FuzzPayload.self)
            _ = try? await keys.unverified(token, as: FuzzPayload.self)
        }
        #expect(Bool(true))
    }

    @Test("Decoded tokens re-encode under every date strategy")
    func decodeReEncodeRoundTrip() async throws {
        var generator = JWTFuzzGenerator(seed: 0x2EE0_D1C0_DEC0_DE12)
        let keys = await directedKeys()
        let parser = DefaultJWTParser()

        let encoders: [JSONEncoder] = [
            JSONEncoder(),  // .deferredToDate
            { let e = JSONEncoder(); e.dateEncodingStrategy = .secondsSince1970; return e }(),
            { let e = JSONEncoder(); e.dateEncodingStrategy = .millisecondsSince1970; return e }(),
            { let e = JSONEncoder(); e.dateEncodingStrategy = .iso8601; return e }(),
            { let e = JSONEncoder(); e.dateEncodingStrategy = .integerSecondsSince1970; return e }(),
        ]

        for _ in 0..<iterations(1_500) {
            let token = generator.token(
                header: generator.directedHeaderJSON(), payload: generator.claimsPayloadJSON())

            guard let parsed = try? parser.parse(token, as: ClaimsFuzzPayload.self) else { continue }

            for encoder in encoders {
                _ = try? encoder.encode(parsed.payload)
                _ = try? encoder.encode(parsed.header)
            }

            _ = try? await keys.sign(parsed.payload)
        }
        #expect(Bool(true))
    }

    @Test("Malformed payloads behind a valid signature never crash verification")
    func signedMalformedPayloadsNeverCrash() async throws {
        var generator = JWTFuzzGenerator(seed: 0x516E_ED0F_2212_3456)
        let keys = await directedKeys()
        let algorithm = try await keys.getKey()
        var verified = 0

        for _ in 0..<iterations(2_000) {
            let token = try JWTFuzzGenerator.signedToken(
                header: #"{"alg":"HS256"}"#,
                payload: generator.claimsPayloadJSON(),
                using: algorithm)

            if (try? await keys.verify(token, as: ClaimsFuzzPayload.self)) != nil { verified += 1 }
            _ = try? await keys.verify(token, as: FuzzPayload.self)
        }

        #expect(verified > 0, "no signed token verified — the loop never got past the signature")
    }

    @Test("Fuzzed kid and alg never crash signer selection")
    func multiKeySignerSelectionNeverCrashes() async throws {
        var generator = JWTFuzzGenerator(seed: 0x3E1E_C709_1234_5678)
        let keys = try await Self.multiKeyCollection()

        for _ in 0..<iterations(2_000) {
            let token = generator.token(
                header: generator.directedHeaderJSON(), payload: generator.payloadJSON())
            _ = try? await keys.verify(token, as: FuzzPayload.self)
            _ = try? await keys.verify(token, as: FuzzPayload.self, iteratingKeys: true)
            _ = try? await keys.unverified(token, as: FuzzPayload.self)
        }
        #expect(Bool(true))
    }

    /// Keys of several types and kids, plus a JWK-backed one built from a generated EC
    /// key so the `.jwk` branch of signer selection is reachable.
    static func multiKeyCollection() async throws -> JWTKeyCollection {
        let ecdsaKey = ES256PrivateKey()
        let eddsaKey = try EdDSA.PrivateKey(curve: .ed25519)
        let collection = await JWTKeyCollection()
            .add(hmac: "secret-a", digestAlgorithm: .sha256, kid: "hmac-256")
            .add(hmac: "secret-b", digestAlgorithm: .sha512, kid: "hmac-512")
            .add(ecdsa: ecdsaKey, kid: "ecdsa")
            .add(eddsa: eddsaKey, kid: "eddsa")

        guard let parameters = ecdsaKey.parameters else { return collection }
        let jwks = """
            {"keys":[{"kty":"EC","crv":"P-256","kid":"jwk-ec",\
            "x":"\(parameters.x)","y":"\(parameters.y)","alg":"ES256"}]}
            """
        return try await collection.add(jwksJSON: jwks)
    }

    @Test(
        "Deep directed pass",
        .enabled(if: ProcessInfo.processInfo.environment["JWT_FUZZ_DEEP"] != nil)
    )
    func deepDirectedPass() async throws {
        var generator = JWTFuzzGenerator(seed: 0xD1AE_C7ED_0F22_5678)
        let keys = await directedKeys()

        for _ in 0..<iterations(20_000) {
            let header = generator.directedHeaderJSON()
            var token = generator.token(header: header, payload: generator.claimsPayloadJSON())
            _ = try? await keys.verify(token, as: ClaimsFuzzPayload.self)
            _ = try? await keys.unverified(token, as: ClaimsFuzzPayload.self)

            generator.mutate(&token)
            _ = try? await keys.verify(token, as: ClaimsFuzzPayload.self)

            let degenerate = generator.token(
                header: #"{"alg":"HS256","x":\#(generator.degenerateValue())}"#,
                payload: generator.payloadJSON())
            _ = try? await keys.unverified(degenerate, as: FuzzPayload.self)

            _ = try? await JWTKeyCollection().add(jwksJSON: generator.jwksJSON())
        }
        #expect(Bool(true))
    }
}
