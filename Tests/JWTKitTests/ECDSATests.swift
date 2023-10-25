import BigInt
@testable import JWTKit
import XCTest

final class ECDSATests: XCTestCase {
    func testECDSADocs() throws {
        let signers = JWTSigners()
        XCTAssertNoThrow(try signers.use(.es256(key: .public(pem: ecdsaPublicKey))))
    }

    func testECDSAGenerate() throws {
        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let signer = try JWTSigner.es256(key: .generate())
        let token = try signer.sign(payload)
        try XCTAssertEqual(signer.verify(token, as: TestPayload.self), payload)
    }

    func testECDSAPublicPrivate() throws {
        let publicSigner = try JWTSigner.es256(key: .public(pem: ecdsaPublicKey))
        let privateSigner = try JWTSigner.es256(key: .private(pem: ecdsaPrivateKey))

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        for _ in 0 ..< 1000 {
            let token = try privateSigner.sign(payload)
            // test private signer decoding
            try XCTAssertEqual(privateSigner.verify(token, as: TestPayload.self), payload)
            // test public signer decoding
            try XCTAssertEqual(publicSigner.verify(token, as: TestPayload.self), payload)
        }
    }

    func testGetECParametersP256() throws {
        let message = "test".bytes

        let ec = try P256Key.generate()
        let ecSigner = JWTSigner.es256(key: ec)

        let signature = try ecSigner.algorithm.sign(message)

        let params = ec.parameters!
        let ecVerifier = try JWTSigner.es256(key: P256Key(parameters: params))
        XCTAssertTrue(try ecVerifier.algorithm.verify(signature, signs: message))
        XCTAssertEqual(ec.curve, .p256)
    }

    func testGetECParametersP384() throws {
        let message = "test".bytes

        let ec = try P384Key.generate()
        let ecSigner = JWTSigner.es384(key: ec)

        let signature = try ecSigner.algorithm.sign(message)

        let params = ec.parameters!
        let ecVerifier = try JWTSigner.es384(key: .init(parameters: params))
        XCTAssertTrue(try ecVerifier.algorithm.verify(signature, signs: message))
        XCTAssertEqual(ec.curve, .p384)
    }

    func testGetECParametersP521() throws {
        let message = "test".bytes

        let ec = try P521Key.generate()
        let ecSigner = JWTSigner.es512(key: ec)

        let signature = try ecSigner.algorithm.sign(message)

        let params = ec.parameters!
        let ecVerifier = try JWTSigner.es512(key: P521Key(parameters: params))
        XCTAssertTrue(try ecVerifier.algorithm.verify(signature, signs: message))
        XCTAssertEqual(ec.curve, .p521)
    }

    func testVerifyingECDSAKeyUsingJWK() throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: JWTSigner) throws {}
        }

        // ecdsa key
        let x = "0tu/H2ShuV8RIgoOxFneTdxmQQYsSk5LdCPuEIBXT+hHd0ufc/OwjEbqilsYnTdm"
        let y = "RWRZz+tP83N0CGwroGyFVgH3PYAO6Oewpu4Xf6EXCp4+sU8uWegwjd72sBK6axj7"

        let privateKey = "k+1LAHQRSSMcyaouYK0YOzRbUKj6ISnvihO2XdLQZHQgMt9BkuCT0+539FSHmJxg"

        // sign jwt
        let privateSigner = try JWTSigner.es384(key: ECDSAKey(parameters: .init(x: x, y: y), privateKey: privateKey))

        let jwt = try privateSigner.sign(Foo(bar: 42), kid: "vapor")

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

        let signers = JWTSigners()
        try signers.use(jwksJSON: jwksString)
        let foo = try signers.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }

    func testVerifyingECDSAKeyUsingJWKBase64URL() throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: JWTSigner) throws {}
        }

        // ecdsa key in base64url format
        let x = "0tu_H2ShuV8RIgoOxFneTdxmQQYsSk5LdCPuEIBXT-hHd0ufc_OwjEbqilsYnTdm"
        let y = "RWRZz-tP83N0CGwroGyFVgH3PYAO6Oewpu4Xf6EXCp4-sU8uWegwjd72sBK6axj7"

        // private key in base64url format
        let privateKey = "k-1LAHQRSSMcyaouYK0YOzRbUKj6ISnvihO2XdLQZHQgMt9BkuCT0-539FSHmJxg"

        // sign jwt
        let privateSigner = try JWTSigner.es384(key: ECDSAKey(parameters: .init(x: x, y: y), privateKey: privateKey))

        let jwt = try privateSigner.sign(Foo(bar: 42), kid: "vapor")

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

        let signers = JWTSigners()
        try signers.use(jwksJSON: jwksString)
        let foo = try signers.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }

    func testVerifyingECDSAKeyUsingJWKWithMixedBase64Formats() throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: JWTSigner) throws {}
        }

        // ecdsa key in base64url format
        let x = "0tu_H2ShuV8RIgoOxFneTdxmQQYsSk5LdCPuEIBXT-hHd0ufc_OwjEbqilsYnTdm"
        let y = "RWRZz-tP83N0CGwroGyFVgH3PYAO6Oewpu4Xf6EXCp4-sU8uWegwjd72sBK6axj7"

        // private key in base64 format
        let privateKey = "k+1LAHQRSSMcyaouYK0YOzRbUKj6ISnvihO2XdLQZHQgMt9BkuCT0+539FSHmJxg"

        // sign jwt
        let privateSigner = try JWTSigner.es384(key: ECDSAKey(parameters: .init(x: x, y: y), privateKey: privateKey))

        let jwt = try privateSigner.sign(Foo(bar: 42), kid: "vapor")

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

        let signers = JWTSigners()
        try signers.use(jwksJSON: jwksString)
        let foo = try signers.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }

    func testJWTPayloadVerification() throws {
        struct NotBar: Error {
            let foo: String
        }
        struct Payload: JWTPayload {
            let foo: String
            func verify(using _: JWTSigner) throws {
                guard foo == "bar" else {
                    throw NotBar(foo: foo)
                }
            }
        }

        let signer = try JWTSigner.es256(key: .generate())
        do {
            let token = try signer.sign(Payload(foo: "qux"))
            _ = try signer.verify(token, as: Payload.self)
        } catch let error as NotBar {
            XCTAssertEqual(error.foo, "qux")
        }
        do {
            let token = try signer.sign(Payload(foo: "bar"))
            let payload = try signer.verify(token, as: Payload.self)
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
