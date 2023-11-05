import BigInt
@testable import JWTKit
import XCTest

final class ECDSATests: XCTestCase {
    func testECDSADocs() async throws {
        XCTAssertNoThrow(try ES256Key.public(pem: ecdsaPublicKey))
    }

    func testECDSAGenerate() async throws {
        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let keyCollection = JWTKeyCollection()
        try await keyCollection.addES256(key: ES256Key.generate())
        let token = try await keyCollection.sign(payload)
        try await XCTAssertEqualAsync(await keyCollection.verify(token, as: TestPayload.self), payload)
    }

    func testECDSAPublicPrivate() async throws {
        let keys = try await JWTKeyCollection()
            .addES256(key: ES256Key.public(pem: ecdsaPublicKey), kid: "public")
            .addES256(key: ES256Key.private(pem: ecdsaPrivateKey), kid: "private")

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        for _ in 0 ..< 1000 {
            let token = try await keys.sign(payload, kid: "private")
            // test private signer decoding
            try await XCTAssertEqualAsync(await keys.verify(token, as: TestPayload.self), payload)
            // test public signer decoding
            try await XCTAssertEqualAsync(await keys.verify(token, as: TestPayload.self), payload)
        }
    }

    func testGetECParametersES256() async throws {
        let message = "test".bytes

        let ec = try ES256Key.generate()
        let keys = await JWTKeyCollection().addES256(key: ec, kid: "initial")

        let signature = try await keys.getKey(for: "initial").sign(message)

        let params = ec.parameters!
        try await keys.addES256(key: ES256Key(parameters: params), kid: "params")
        try await XCTAssertTrueAsync(try await keys.getKey(for: "params").verify(signature, signs: message))
        XCTAssertEqual(ec.curve, .p256)
    }

    func testGetECParametersES384() async throws {
        let message = "test".bytes

        let ec = try ES384Key.generate()
        let keys = await JWTKeyCollection().addES384(key: ec, kid: "initial")

        let signature = try await keys.getKey(for: "initial").sign(message)

        let params = ec.parameters!
        try await keys.addES384(key: ES384Key(parameters: params), kid: "params")
        try await XCTAssertTrueAsync(try await keys.getKey(for: "params").verify(signature, signs: message))
        XCTAssertEqual(ec.curve, .p384)
    }

    func testGetECParametersES521() async throws {
        let message = "test".bytes

        let ec = try ES521Key.generate()
        let keys = await JWTKeyCollection().addES521(key: ec, kid: "initial")

        let signature = try await keys.getKey(for: "initial").sign(message)

        let params = ec.parameters!
        try await keys.addES521(key: ES521Key(parameters: params), kid: "params")
        try await XCTAssertTrueAsync(try await keys.getKey(for: "params").verify(signature, signs: message))
        XCTAssertEqual(ec.curve, .p521)
    }

    func testVerifyingECDSAKeyUsingJWK() async throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: JWTAlgorithm) throws {}
        }

        // ecdsa key
        let x = "0tu/H2ShuV8RIgoOxFneTdxmQQYsSk5LdCPuEIBXT+hHd0ufc/OwjEbqilsYnTdm"
        let y = "RWRZz+tP83N0CGwroGyFVgH3PYAO6Oewpu4Xf6EXCp4+sU8uWegwjd72sBK6axj7"

        let privateKey = "k+1LAHQRSSMcyaouYK0YOzRbUKj6ISnvihO2XdLQZHQgMt9BkuCT0+539FSHmJxg"

        // sign jwt
        let key = try ES384Key(parameters: (x, y), privateKey: privateKey)
        let keys = await JWTKeyCollection().addES384(key: key, kid: "vapor")

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

        try await keys.use(jwksJSON: jwksString)
        let foo = try await keys.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }

    func testVerifyingECDSAKeyUsingJWKBase64URL() async throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: JWTAlgorithm) throws {}
        }

        // ecdsa key in base64url format
        let x = "0tu_H2ShuV8RIgoOxFneTdxmQQYsSk5LdCPuEIBXT-hHd0ufc_OwjEbqilsYnTdm"
        let y = "RWRZz-tP83N0CGwroGyFVgH3PYAO6Oewpu4Xf6EXCp4-sU8uWegwjd72sBK6axj7"

        // private key in base64url format
        let privateKey = "k-1LAHQRSSMcyaouYK0YOzRbUKj6ISnvihO2XdLQZHQgMt9BkuCT0-539FSHmJxg"

        // sign jwt
        let key = try ES384Key(parameters: (x, y), privateKey: privateKey)
        let keys = await JWTKeyCollection().addES384(key: key, kid: "vapor")

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

        try await keys.use(jwksJSON: jwksString)
        let foo = try await keys.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }

    func testVerifyingECDSAKeyUsingJWKWithMixedBase64Formats() async throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: JWTAlgorithm) throws {}
        }

        // ecdsa key in base64url format
        let x = "0tu_H2ShuV8RIgoOxFneTdxmQQYsSk5LdCPuEIBXT-hHd0ufc_OwjEbqilsYnTdm"
        let y = "RWRZz-tP83N0CGwroGyFVgH3PYAO6Oewpu4Xf6EXCp4-sU8uWegwjd72sBK6axj7"

        // private key in base64 format
        let privateKey = "k+1LAHQRSSMcyaouYK0YOzRbUKj6ISnvihO2XdLQZHQgMt9BkuCT0+539FSHmJxg"

        // sign jwt
        let key = try ES384Key(parameters: (x, y), privateKey: privateKey)
        let keys = await JWTKeyCollection().addES384(key: key, kid: "vapor")

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

        try await keys.use(jwksJSON: jwksString)
        let foo = try await keys.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }

    func testJWTPayloadVerification() async throws {
        struct NotBar: Error {
            let foo: String
        }
        struct Payload: JWTPayload {
            let foo: String
            func verify(using _: JWTAlgorithm) throws {
                guard foo == "bar" else {
                    throw NotBar(foo: foo)
                }
            }
        }

        let keys = try await JWTKeyCollection().addES256(key: ES256Key.generate(), kid: "vapor")

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
