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
