#if canImport(Testing)
import Testing
import Crypto
import JWTKit

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

@Suite("ECDSA Tests")
struct ECDSATests {

    @Test("Test ECDSA Docs")
    func ecdsaDocs() async throws {
        #expect(throws: Never.self) {
            try ES256PublicKey(pem: ecdsaPublicKey)
        }
    }

    @Test("Test ECDSA from Crypto Key")
    func ecdsaFromCryptoKey() async throws {
        let key = try P256.Signing.PublicKey(pemRepresentation: ecdsaPublicKey)
        let cryptoKey = try ES256PublicKey(backing: key)
        let otherKey = try ES256PublicKey(pem: ecdsaPublicKey)
        #expect(cryptoKey == otherKey)
    }

    @Test("Test ECDSA Private from Crypto Key")
    func ecdsaPrivateFromCryptoKey() async throws {
        let key = try P256.Signing.PrivateKey(pemRepresentation: ecdsaPrivateKey)
        let cryptoKey = try ES256PrivateKey(backing: key)
        let otherKey = try ES256PrivateKey(pem: ecdsaPrivateKey)
        #expect(cryptoKey == otherKey)
    }

    @Test("Test Signing with Public Key")
    func signingWithPublicKey() async throws {
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

        await #expect {
            try await keys.sign(payload, kid: "public")
        } throws: { error in
            guard let error = error as? JWTError else {
                return false
            }
            return error.errorType == .signingAlgorithmFailure
        }
    }

    @Test("Test ECDSA Generate")
    func ecdsaGenerate() async throws {
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
        let verifiedPayload = try await keyCollection.verify(token, as: TestPayload.self)
        #expect(verifiedPayload == payload)
    }

    @Test("Test ECDSA Public and Private")
    func ecdsaPublicPrivate() async throws {
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
            #expect(try await keys.verify(token, as: TestPayload.self) == payload)
            #expect(try await keys.verify(token, as: TestPayload.self) == payload)
        }
    }

    @Test("Test Verifying ECDSA Key Using JWK")
    func verifyingECDSAKeyUsingJWK() async throws {
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
        #expect(foo.bar == 42)
    }

    @Test("Test Verifying ECDSA Key Using JWK Base64URL")
    func verifyingECDSAKeyUsingJWKBase64URL() async throws {
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
        #expect(foo.bar == 42)
    }

    @Test("Test Verifying ECDSA Key Using JWK With Mixed Base64 Formats")
    func verifyingECDSAKeyUsingJWKWithMixedBase64Formats() async throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: some JWTAlgorithm) throws {}
        }

        // ECDSA key in base64url format
        let x = "0tu_H2ShuV8RIgoOxFneTdxmQQYsSk5LdCPuEIBXT-hHd0ufc_OwjEbqilsYnTdm"
        let y = "RWRZz-tP83N0CGwroGyFVgH3PYAO6Oewpu4Xf6EXCp4-sU8uWegwjd72sBK6axj7"

        // Private key in base64 format
        let privateKey = "k+1LAHQRSSMcyaouYK0YOzRbUKj6ISnvihO2XdLQZHQgMt9BkuCT0+539FSHmJxg"

        // Sign JWT
        let key = try ES384PrivateKey(key: privateKey)
        let keys = await JWTKeyCollection().add(ecdsa: key, kid: "vapor")

        let jwt = try await keys.sign(Foo(bar: 42), kid: "vapor")

        // Verify using JWK without alg
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

        #expect(foo.bar == 42)
    }

    @Test("Test JWT Payload Verification")
    func jwtPayloadVerification() async throws {
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

        // First test: "qux" payload should throw NotBar error
        await #expect(
            performing: {
                let token = try await keys.sign(Payload(foo: "qux"))
                _ = try await keys.verify(token, as: Payload.self)
            },
            throws: { error in
                guard let error = error as? NotBar else {
                    return false
                }
                return error.foo == "qux"
            }
        )

        // Second test: "bar" payload should pass verification
        let token = try await keys.sign(Payload(foo: "bar"))
        let payload = try await keys.verify(token, as: Payload.self)
        #expect(payload.foo == "bar")
    }

    @Test("Test Export Public Key as PEM")
    func exportPublicKeyAsPEM() async throws {
        let key = try ES256PublicKey(pem: ecdsaPublicKey)
        let key2 = try ES256PublicKey(pem: key.pemRepresentation)
        #expect(key == key2)
    }

    @Test("Test Export Private Key as PEM")
    func exportPrivateKeyAsPEM() async throws {
        let key = try ES256PrivateKey(pem: ecdsaPrivateKey)
        let key2 = try ES256PrivateKey(pem: key.pemRepresentation)
        #expect(key == key2)
    }

    @Test("Test Get EC Parameters ES256")
    func getECParametersES256() async throws {
        let message = "test".bytes

        // Create ES256 private key
        let ec = ES256PrivateKey()
        let keys = await JWTKeyCollection().add(ecdsa: ec, kid: "initial")

        // Sign the message with the initial private key
        let signature = try await keys.getKey(for: "initial").sign(message)

        // Extract the EC parameters and create a public key from it
        let params = ec.parameters!
        try await keys.add(ecdsa: ES256PublicKey(parameters: params), kid: "params")

        // Verify the signature using the public key created from the parameters
        #expect(try await keys.getKey(for: "params").verify(signature, signs: message))

        // Ensure the curve is p256
        #expect(ec.curve == .p256)
    }

    @Test("Test Get EC Parameters ES384")
    func getECParametersES384() async throws {
        let message = "test".bytes

        // Create ES384 private key
        let ec = ES384PrivateKey()
        let keys = await JWTKeyCollection().add(ecdsa: ec, kid: "initial")

        // Sign the message with the initial private key
        let signature = try await keys.getKey(for: "initial").sign(message)

        // Extract the EC parameters and create a public key from it
        let params = ec.parameters!
        try await keys.add(ecdsa: ES384PublicKey(parameters: params), kid: "params")

        // Verify the signature using the public key created from the parameters
        #expect(try await keys.getKey(for: "params").verify(signature, signs: message))

        // Ensure the curve is p384
        #expect(ec.curve == .p384)
    }

    @Test("Test Get EC Parameters ES512")
    func getECParametersES512() async throws {
        let message = "test".bytes

        // Create ES512 private key
        let ec = ES512PrivateKey()
        let keys = await JWTKeyCollection().add(ecdsa: ec, kid: "initial")

        // Sign the message with the initial private key
        let signature = try await keys.getKey(for: "initial").sign(message)

        // Extract the EC parameters and create a public key from it
        let params = ec.parameters!
        try await keys.add(ecdsa: ES512PublicKey(parameters: params), kid: "params")

        // Verify the signature using the public key created from the parameters
        #expect(try await keys.getKey(for: "params").verify(signature, signs: message))

        // Ensure the curve is p521
        #expect(ec.curve == .p521)
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
#endif  // canImport(Testing)
