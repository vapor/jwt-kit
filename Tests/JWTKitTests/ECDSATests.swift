import Crypto
import JWTKit
import XCTest

final class ECDSATests: XCTestCase, @unchecked Sendable {
    func testECDSADocs() async throws {
        XCTAssertNoThrow(try ES256PublicKey(pem: ecdsaPublicKey))
    }

    func testECDSAFromCryptoKey() async throws {
        let key = try P256.Signing.PublicKey(pemRepresentation: ecdsaPublicKey)
        let cryptoKey = try ES256PublicKey(backing: key)
        let otherKey = try ES256PublicKey(pem: ecdsaPublicKey)
        XCTAssertEqual(cryptoKey, otherKey)
    }

    func testECDSAPrivateFromCryptoKey() async throws {
        let key = try P256.Signing.PrivateKey(pemRepresentation: ecdsaPrivateKey)
        let cryptoKey = try ES256PrivateKey(backing: key)
        let otherKey = try ES256PrivateKey(pem: ecdsaPrivateKey)
        XCTAssertEqual(cryptoKey, otherKey)
    }

    func testSigningWithPublicKey() async throws {
        let key = try ES256PrivateKey(pem: ecdsaPrivateKey)
        let publicKey = try ES256PublicKey(pem: ecdsaPublicKey)
        let keys = await JWTKeyCollection()
            .add(ecdsa: key, kid: "private")
            .add(ecdsa: publicKey, kid: "public")

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        await XCTAssertThrowsErrorAsync(try await keys.sign(payload, kid: "public")) { error in
            guard let error = error as? JWTError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
            XCTAssertEqual(error.errorType, .signingAlgorithmFailure)
        }
    }

    func testECDSAGenerate() async throws {
        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let keyCollection = JWTKeyCollection()
        let key = ES256PrivateKey()
        await keyCollection.add(ecdsa: key)
        let token = try await keyCollection.sign(payload)
        try await XCTAssertEqualAsync(
            await keyCollection.verify(token, as: TestPayload.self), payload)
    }

    func testECDSAPublicPrivate() async throws {
        let keys = try await JWTKeyCollection()
            .add(ecdsa: ES256PublicKey(pem: ecdsaPublicKey), kid: "public")
            .add(ecdsa: ES256PrivateKey(pem: ecdsaPrivateKey), kid: "private")

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        for _ in 0..<1000 {
            let token = try await keys.sign(payload, kid: "private")
            // test private signer decoding
            try await XCTAssertEqualAsync(await keys.verify(token, as: TestPayload.self), payload)
            // test public signer decoding
            try await XCTAssertEqualAsync(await keys.verify(token, as: TestPayload.self), payload)
        }
    }

    func testVerifyingECDSAKeyUsingJWK() async throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: some JWTAlgorithm) throws {}
        }

        // ecdsa key
        let x = "0tu/H2ShuV8RIgoOxFneTdxmQQYsSk5LdCPuEIBXT+hHd0ufc/OwjEbqilsYnTdm"
        let y = "RWRZz+tP83N0CGwroGyFVgH3PYAO6Oewpu4Xf6EXCp4+sU8uWegwjd72sBK6axj7"

        let privateKey = "k+1LAHQRSSMcyaouYK0YOzRbUKj6ISnvihO2XdLQZHQgMt9BkuCT0+539FSHmJxg"

        // sign jwt
        let key = try ES384PrivateKey(key: privateKey)
        let keys = await JWTKeyCollection().add(ecdsa: key, kid: "vapor")

        let jwt = try await keys.sign(Foo(bar: 42), kid: "vapor")

        // verify using jwks without alg
        let jwksString = """
            {
                "keys": [
                    {
                        "kty": "EC",
                        "use": "sig",
                        "kid": "vapor",
                        "x": "\(x)",
                        "y": "\(y)"
                     }
                ]
            }
            """

        try await keys.add(jwksJSON: jwksString)
        let foo = try await keys.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }

    func testVerifyingECDSAKeyUsingJWKBase64URL() async throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: some JWTAlgorithm) throws {}
        }

        // ecdsa key in base64url format
        let x = "0tu_H2ShuV8RIgoOxFneTdxmQQYsSk5LdCPuEIBXT-hHd0ufc_OwjEbqilsYnTdm"
        let y = "RWRZz-tP83N0CGwroGyFVgH3PYAO6Oewpu4Xf6EXCp4-sU8uWegwjd72sBK6axj7"

        // private key in base64url format
        let privateKey = "k-1LAHQRSSMcyaouYK0YOzRbUKj6ISnvihO2XdLQZHQgMt9BkuCT0-539FSHmJxg"

        // sign jwt
        let key = try ES384PrivateKey(key: privateKey)
        let keys = await JWTKeyCollection().add(ecdsa: key, kid: "vapor")

        let jwt = try await keys.sign(Foo(bar: 42), kid: "vapor")

        // verify using jwks without alg
        let jwksString = """
            {
                "keys": [
                    {
                        "kty": "EC",
                        "use": "sig",
                        "kid": "vapor",
                        "x": "\(x)",
                        "y": "\(y)"
                     }
                ]
            }
            """

        try await keys.add(jwksJSON: jwksString)
        let foo = try await keys.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }

    func testVerifyingECDSAKeyUsingJWKWithMixedBase64Formats() async throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: some JWTAlgorithm) throws {}
        }

        // ecdsa key in base64url format
        let x = "0tu_H2ShuV8RIgoOxFneTdxmQQYsSk5LdCPuEIBXT-hHd0ufc_OwjEbqilsYnTdm"
        let y = "RWRZz-tP83N0CGwroGyFVgH3PYAO6Oewpu4Xf6EXCp4-sU8uWegwjd72sBK6axj7"

        // private key in base64 format
        let privateKey = "k+1LAHQRSSMcyaouYK0YOzRbUKj6ISnvihO2XdLQZHQgMt9BkuCT0+539FSHmJxg"

        // sign jwt
        let key = try ES384PrivateKey(key: privateKey)
        let keys = await JWTKeyCollection().add(ecdsa: key, kid: "vapor")

        let jwt = try await keys.sign(Foo(bar: 42), kid: "vapor")

        // verify using jwks without alg
        let jwksString = """
            {
                "keys": [
                    {
                        "kty": "EC",
                        "use": "sig",
                        "kid": "vapor",
                        "x": "\(x)",
                        "y": "\(y)"
                     }
                ]
            }
            """

        try await keys.add(jwksJSON: jwksString)
        let foo = try await keys.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }

    func testJWTPayloadVerification() async throws {
        struct NotBar: Error {
            let foo: String
        }
        struct Payload: JWTPayload {
            let foo: String
            func verify(using _: some JWTAlgorithm) throws {
                guard self.foo == "bar" else {
                    throw NotBar(foo: self.foo)
                }
            }
        }

        let keys = await JWTKeyCollection().add(ecdsa: ES256PrivateKey(), kid: "vapor")

        do {
            let token = try await keys.sign(Payload(foo: "qux"))
            _ = try await keys.verify(token, as: Payload.self)
        } catch let error as NotBar {
            XCTAssertEqual(error.foo, "qux")
        }
        do {
            let token = try await keys.sign(Payload(foo: "bar"))
            let payload = try await keys.verify(token, as: Payload.self)
            XCTAssertEqual(payload.foo, "bar")
        }
    }

    func testExportPublicKeyAsPEM() async throws {
        let key = try ES256PublicKey(pem: ecdsaPublicKey)
        let key2 = try ES256PublicKey(pem: key.pemRepresentation)
        XCTAssertEqual(key, key2)
    }

    func testExportPrivateKeyAsPEM() async throws {
        let key = try ES256PrivateKey(pem: ecdsaPrivateKey)
        let key2 = try ES256PrivateKey(pem: key.pemRepresentation)
        XCTAssertEqual(key, key2)
    }

    func testGetECParametersES256() async throws {
        let message = "test".bytes

        let ec = ES256PrivateKey()
        let keys = await JWTKeyCollection().add(ecdsa: ec, kid: "initial")

        let signature = try await keys.getKey(for: "initial").sign(message)

        let params = ec.parameters!
        try await keys.add(ecdsa: ES256PublicKey(parameters: params), kid: "params")
        try await XCTAssertTrueAsync(
            try await keys.getKey(for: "params").verify(signature, signs: message))
        XCTAssertEqual(ec.curve, .p256)
    }

    func testGetECParametersES384() async throws {
        let message = "test".bytes

        let ec = ES384PrivateKey()
        let keys = await JWTKeyCollection().add(ecdsa: ec, kid: "initial")

        let signature = try await keys.getKey(for: "initial").sign(message)

        let params = ec.parameters!
        try await keys.add(ecdsa: ES384PublicKey(parameters: params), kid: "params")
        try await XCTAssertTrueAsync(
            try await keys.getKey(for: "params").verify(signature, signs: message))
        XCTAssertEqual(ec.curve, .p384)
    }

    func testGetECParametersES512() async throws {
        let message = "test".bytes

        let ec = ES512PrivateKey()
        let keys = await JWTKeyCollection().add(ecdsa: ec, kid: "initial")

        let signature = try await keys.getKey(for: "initial").sign(message)

        let params = ec.parameters!
        try await keys.add(ecdsa: ES512PublicKey(parameters: params), kid: "params")
        try await XCTAssertTrueAsync(
            try await keys.getKey(for: "params").verify(signature, signs: message))
        XCTAssertEqual(ec.curve, .p521)
    }
}

let ecdsaPrivateKey = """
    -----BEGIN PRIVATE KEY-----
    MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg2sD+kukkA8GZUpmm
    jRa4fJ9Xa/JnIG4Hpi7tNO66+OGgCgYIKoZIzj0DAQehRANCAATZp0yt0btpR9kf
    ntp4oUUzTV0+eTELXxJxFvhnqmgwGAm1iVW132XLrdRG/ntlbQ1yzUuJkHtYBNve
    y+77Vzsd
    -----END PRIVATE KEY-----
    """
let ecdsaPublicKey = """
    -----BEGIN PUBLIC KEY-----
    MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2adMrdG7aUfZH57aeKFFM01dPnkx
    C18ScRb4Z6poMBgJtYlVtd9ly63URv57ZW0Ncs1LiZB7WATb3svu+1c7HQ==
    -----END PUBLIC KEY-----
    """
