#if canImport(Testing)
import Testing
import JWTKit

@Suite("EdDSA Tests")
struct EdDSATests {

    @Test("Test EdDSA Generate")
    func edDSAGenerate() async throws {
        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let keyCollection = try await JWTKeyCollection()
            .add(eddsa: EdDSA.PrivateKey(curve: .ed25519))

        let token = try await keyCollection.sign(payload)
        let verifiedPayload = try await keyCollection.verify(token, as: TestPayload.self)
        #expect(verifiedPayload == payload)
    }

    @Test("Test EdDSA Public and Private")
    func edDSAPublicPrivate() async throws {
        let keys = try await JWTKeyCollection()
            .add(eddsa: EdDSA.PublicKey(x: eddsaPublicKeyBase64, curve: .ed25519), kid: "public")
            .add(eddsa: EdDSA.PrivateKey(d: eddsaPrivateKeyBase64, curve: .ed25519), kid: "private")

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        for _ in 0..<1000 {
            let token = try await keys.sign(payload, kid: "private")
            // test public signer decoding
            let verifiedPayload = try await keys.verify(token, as: TestPayload.self)
            #expect(verifiedPayload == payload)
        }
    }

    @Test("Test Verifying EdDSA Key Using JWK")
    func verifyingEdDSAKeyUsingJWK() async throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: some JWTAlgorithm) throws {}
        }

        // ecdsa key in base64 format
        let x = eddsaPublicKeyBase64
        let d = eddsaPrivateKeyBase64

        // sign JWT
        let keyCollection = try await JWTKeyCollection()
            .add(eddsa: EdDSA.PrivateKey(d: d, curve: .ed25519), kid: "vapor")

        let jwt = try await keyCollection.sign(Foo(bar: 42))

        // verify using jwks
        let jwksString = """
            {
                "keys": [
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "use": "sig",
                        "kid": "vapor",
                        "x": "\(x)",
                        "d": "\(d)"
                    }
                ]
            }
            """

        try await keyCollection.add(jwksJSON: jwksString)
        let foo = try await keyCollection.verify(jwt, as: Foo.self)
        #expect(foo.bar == 42)
    }

    @Test("Test Verifying EdDSA Key Using JWK Base64URL")
    func verifyingEdDSAKeyUsingJWKBase64URL() async throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: some JWTAlgorithm) throws {}
        }

        let x = eddsaPublicKeyBase64Url
        let d = eddsaPrivateKeyBase64Url

        // sign JWT
        let keyCollection = try await JWTKeyCollection()
            .add(eddsa: EdDSA.PrivateKey(d: d, curve: .ed25519), kid: "vapor")

        let jwt = try await keyCollection.sign(Foo(bar: 42))

        // verify using jwks
        let jwksString = """
            {
                "keys": [
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "use": "sig",
                        "kid": "vapor",
                        "x": "\(x)",
                        "d": "\(d)"
                    }
                ]
            }
            """

        try await keyCollection.add(jwksJSON: jwksString)
        let foo = try await keyCollection.verify(jwt, as: Foo.self)
        #expect(foo.bar == 42)
    }

    @Test("Test Verifying EdDSA Key Using JWK with Mixed Base64 Formats")
    func verifyingEdDSAKeyUsingJWKWithMixedBase64Formats() async throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: some JWTAlgorithm) throws {}
        }

        // eddsa key in base64url format
        let x = eddsaPublicKeyBase64Url
        let d = eddsaPrivateKeyBase64

        // sign JWT
        let keyCollection = try await JWTKeyCollection()
            .add(eddsa: EdDSA.PrivateKey(d: d, curve: .ed25519), kid: "vapor")

        let jwt = try await keyCollection.sign(Foo(bar: 42), kid: "vapor")

        // verify using jwks
        let jwksString = """
            {
                "keys": [
                    {
                        "kty": "OKP",
                        "crv": "Ed25519",
                        "use": "sig",
                        "kid": "vapor",
                        "x": "\(x)",
                        "d": "\(d)"
                    }
                ]
            }
            """

        try await keyCollection.add(jwksJSON: jwksString)
        let foo = try await keyCollection.verify(jwt, as: Foo.self)
        #expect(foo.bar == 42)
    }
}

let eddsaPublicKeyBase64 = "0ZcEvMCSYqSwR8XIkxOoaYjRQSAO8frTMSCpNbUl4lE="
let eddsaPrivateKeyBase64 = "d1H3/dcg0V3XyAuZW2TE5Z3rhY20M+4YAfYu/HUQd8w="
let eddsaPublicKeyBase64Url = "0ZcEvMCSYqSwR8XIkxOoaYjRQSAO8frTMSCpNbUl4lE"
let eddsaPrivateKeyBase64Url = "d1H3_dcg0V3XyAuZW2TE5Z3rhY20M-4YAfYu_HUQd8w"
#endif  // canImport(Testing)
