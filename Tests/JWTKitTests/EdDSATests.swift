import JWTKit
import XCTest

final class EdDSATests: XCTestCase {
    func testEdDSAGenerate() throws {
        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let signer = try JWTSigner.eddsa(.generate(curve: .ed25519))
        let token = try signer.sign(payload)
        try XCTAssertEqual(signer.verify(token, as: TestPayload.self), payload)
    }

    func testEdDSAPublicPrivate() throws {
        let publicSigner = try JWTSigner.eddsa(
            .public(x: eddsaPublicKeyBase64, curve: .ed25519)
        )
        let privateSigner = try JWTSigner.eddsa(
            .private(x: eddsaPublicKeyBase64, d: eddsaPrivateKeyBase64, curve: .ed25519)
        )

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        for _ in 0 ..< 1000 {
            let token = try privateSigner.sign(payload)
            // test public signer decoding
            try XCTAssertEqual(publicSigner.verify(token, as: TestPayload.self), payload)
        }
    }

    func testVerifyingEdDSAKeyUsingJWK() throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: JWTSigner) throws {}
        }

        // ecdsa key in base64 format
        let x = eddsaPublicKeyBase64
        let d = eddsaPrivateKeyBase64

        // sign jwt
        let signer = try JWTSigner.eddsa(.private(x: x, d: d, curve: .ed25519))
        let jwt = try signer.sign(Foo(bar: 42), kid: "vapor")

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

        let signers = JWTSigners()
        try signers.use(jwksJSON: jwksString)
        let foo = try signers.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }

    func testVerifyingEdDSAKeyUsingJWKBase64URL() throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: JWTSigner) throws {}
        }

        // eddsa key in base64url format
        let x = eddsaPublicKeyBase64Url
        let d = eddsaPrivateKeyBase64Url

        // sign jwt
        let signer = try JWTSigner.eddsa(.private(x: x, d: d, curve: .ed25519))
        let jwt = try signer.sign(Foo(bar: 42), kid: "vapor")

        // verify using jwks without alg
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

        let signers = JWTSigners()
        try signers.use(jwksJSON: jwksString)
        let foo = try signers.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }

    func testVerifyingEdDSAKeyUsingJWKWithMixedBase64Formats() throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: JWTSigner) throws {}
        }

        // eddsa key in base64url format
        let x = eddsaPublicKeyBase64Url
        let d = eddsaPrivateKeyBase64

        // sign jwt
        let signer = try JWTSigner.eddsa(.private(x: x, d: d, curve: .ed25519))
        let jwt = try signer.sign(Foo(bar: 42), kid: "vapor")

        // verify using jwks without alg
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

        let signers = JWTSigners()
        try signers.use(jwksJSON: jwksString)
        let foo = try signers.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }
}

let eddsaPublicKeyBase64 = "0ZcEvMCSYqSwR8XIkxOoaYjRQSAO8frTMSCpNbUl4lE="
let eddsaPrivateKeyBase64 = "d1H3/dcg0V3XyAuZW2TE5Z3rhY20M+4YAfYu/HUQd8w="
let eddsaPublicKeyBase64Url = "0ZcEvMCSYqSwR8XIkxOoaYjRQSAO8frTMSCpNbUl4lE"
let eddsaPrivateKeyBase64Url = "d1H3_dcg0V3XyAuZW2TE5Z3rhY20M-4YAfYu_HUQd8w"
