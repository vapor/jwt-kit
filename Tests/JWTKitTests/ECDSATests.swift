import BigInt
@testable import JWTKit
import XCTest

final class ECDSATests: XCTestCase {
    func testECDSADocs() throws {
        let signers = JWTSigners()
        try signers.use(.es256(key: .public(pem: ecdsaPublicKey)))
    }

    func testECDSAGenerate() throws {
        let payload = TestPayload(
            subject: "JWTKit",
            expiration: .init(value: .distantFuture),
            admin: true
        )
        let signer = try JWTSigner.es256(key: .generate())
        let token = try signer.sign(payload)
        try XCTAssertEqual(signer.verify(token, as: TestPayload.self), payload)
    }

    func testECDSAPublicPrivate() throws {
        let publicSigner = try JWTSigner.es256(key: .public(pem: ecdsaPublicKey))
        let privateSigner = try JWTSigner.es256(key: .private(pem: ecdsaPrivateKey))

        let payload = TestPayload(
            subject: "JWTKit",
            expiration: .init(value: .distantFuture),
            admin: true
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

//     func testGetECParametersP384() throws {
//         let message = "test".bytes

//         let ec = try ECDSAKey.generate(curve: .p384)
//         let ecSigner = JWTSigner.es384(key: ec)

//         let signature = try ecSigner.algorithm.sign(message)

//         let params = ec.parameters!
//         let ecVerifier = try JWTSigner.es384(key: ECDSAKey(parameters: params, curve: .p384))
//         XCTAssertTrue(try ecVerifier.algorithm.verify(signature, signs: message))
//         XCTAssertEqual(ec.curve, .p384)
//     }

//     func testGetECParametersP521() throws {
//         let message = "test".bytes

//         let ec = try ECDSAKey.generate(curve: .p521)
//         let ecSigner = JWTSigner.es512(key: ec)

//         let signature = try ecSigner.algorithm.sign(message)

//         let params = ec.parameters!
//         let ecVerifier = try JWTSigner.es512(key: ECDSAKey(parameters: params, curve: .p521))
//         XCTAssertTrue(try ecVerifier.algorithm.verify(signature, signs: message))
//         XCTAssertEqual(ec.curve, .p521)
//     }
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
