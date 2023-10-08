import BigInt
@testable import JWTKit
import XCTest

final class RSATests: XCTestCase {
    func testCalculatePrimeFactors() throws {
        try wycheproof(fileName: "rsa_oaep_misc_test", testFunction: testPrimeFactor)
        try wycheproof(fileName: "rsa_oaep_2048_sha1_mgf1sha1_test", testFunction: testPrimeFactor)
        try wycheproof(fileName: "rsa_oaep_2048_sha224_mgf1sha1_test", testFunction: testPrimeFactor)
        try wycheproof(fileName: "rsa_oaep_2048_sha256_mgf1sha256_test", testFunction: testPrimeFactor)
    }

    func testCalculateModularInverses() throws {
        try wycheproof(fileName: "rsa_oaep_misc_test", testFunction: testModularInverse)
        try wycheproof(fileName: "rsa_oaep_2048_sha1_mgf1sha1_test", testFunction: testModularInverse)
        try wycheproof(fileName: "rsa_oaep_2048_sha256_mgf1sha256_test", testFunction: testModularInverse)
    }

    func testRSADocs() throws {
        let signers = JWTSigners()
        try signers.use(.rs256(key: .public(pem: publicKey)))
    }

    func testPublicKeyInitialization() throws {
        let rsaKey = try RSAKey(modulus: modulus, exponent: publicExponent)
        XCTAssertNotNil(rsaKey.publicKey)
        XCTAssertNil(rsaKey.privateKey)
    }

    func testPrivateKeyInitialization() throws {
        let rsaKey = try RSAKey(modulus: modulus, exponent: publicExponent, privateExponent: privateExponent)
        XCTAssertNotNil(rsaKey.publicKey)
        XCTAssertNotNil(rsaKey.privateKey)
    }

    func testSigning() throws {
        let privateSigner = try JWTSigner.rs256(key: .private(pem: privateKey))
        let publicSigner = try JWTSigner.rs256(key: .public(pem: publicKey))

        let payload = TestPayload(
            subject: "JWTKit",
            expiration: .init(value: .distantFuture),
            admin: true
        )

        let privateSigned = try privateSigner.sign(payload)
        try XCTAssertEqual(publicSigner.verify(privateSigned, as: TestPayload.self), payload)
        try XCTAssertEqual(privateSigner.verify(privateSigned, as: TestPayload.self), payload)
    }

    func testSigningWithPublic() throws {
        let publicSigner = try JWTSigner.rs256(key: .public(pem: publicKey))

        let payload = TestPayload(
            subject: "vapor",
            expiration: .init(value: .distantFuture),
            admin: false
        )
        XCTAssertThrowsError(_ = try publicSigner.sign(payload))
    }

    func testSigningWithRawBuiltPrivateKey() throws {
        let privateKey = try RSAKey(modulus: modulus, exponent: publicExponent, privateExponent: privateExponent).privateKey!
        let privateSigner = try JWTSigner.rs256(key: .private(pem: privateKey.pemRepresentation))
        let publicSigner = try JWTSigner.rs256(key: .public(pem: privateKey.publicKey.pemRepresentation))

        let payload = TestPayload(
            subject: "JWTKit",
            expiration: .init(value: .distantFuture),
            admin: true
        )

        let privateSigned = try privateSigner.sign(payload)
        try XCTAssertEqual(publicSigner.verify(privateSigned, as: TestPayload.self), payload)
        try XCTAssertEqual(privateSigner.verify(privateSigned, as: TestPayload.self), payload)
    }

    private func testModularInverse(_ testGroup: TestGroup) throws {
        guard let privateKey = testGroup.privateKeyJwk else {
            return
        }

        guard
            let p = privateKey.p.urlDecodedBigUInt,
            let q = privateKey.q.urlDecodedBigUInt,
            let qi = privateKey.qi.urlDecodedBigUInt
        else {
            return XCTFail("Failed to extract or parse prime factors p, q, or qi")
        }

        guard let pInverse = q.inverse(p) else {
            return XCTFail("Failed to calculate the modular inverse of p")
        }
        XCTAssertEqual(pInverse, qi, "The modular inverse of p should equal qi; got \(pInverse) != \(qi)")
    }

    private func testPrimeFactor(_ testGroup: TestGroup) throws {
        guard
            let n = BigUInt(testGroup.n, radix: 16),
            let e = BigUInt(testGroup.e, radix: 16),
            let d = BigUInt(testGroup.d, radix: 16)
        else {
            return XCTFail("Failed to extract or parse modulus 'n', public exponent 'e', or private exponent 'd'")
        }

        let (p, q) = try PrimeGenerator.calculatePrimeFactors(n: n, e: e, d: d)
        XCTAssertEqual(p * q, n, "The product of p and q should equal n; got \(p) * \(q) != \(n)")
    }
}

let modulus = """
00d0941e63a980fa92fb25ed4c7b3307f827023034ae7f1a7491f0699ca7607285e62ad8e994bac21b8b6e305e334f4874067d28e304230dca7f0e85f7ce595770b6e054c9f844ba86c0696eeba0769d8d4a347e8fe85c724ac1c44994af18a39e719f721f1bc50c46a39e6c075fcd1649f01f22608ce7dc6955502258336987d9
"""

let publicExponent = "010001"

let privateExponent = """
5ff4a47e690ea338573e3d8b3fea5c32378ff4296855a51017cba86a9f3de9b1dc0fbe36c76b9bbd1c4a170a5f448c2a8489b3f3ac858be4aacb3daaa14dccc183622eedd3ae6f0427a2a298b51b97818a5430f13705f42d8b25476f939c935e389e30d9ade5d0180920135f5aef0c5fecd15f00b83b51dab8ba930d88826801
"""

let publicKey = """
-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy/FtQ/cOcx6ZgyaqU54C
ESfkpttXuNnEZ07nYXXo8ylIiUFpB0r0Fecgv/tIhF1LFCWBHUsqyoSRQz0/iBRn
YyIsG+yF/q1K3ll5Q/2GAS9/28jBuJGKDuKIj6dgPlr33si6bjeePTl4ZO6OZFxG
Yyn4x035pwGwjKGFuQRKYh0AtxwHiWeRIsAJ/B2Z+VGOpcSXH+x/YUfN8Q9FuyGU
zcsVLuGizbooRSMSSoD/y/8veWOnXWbMsh0KKTON/+yTmAcLn2tOzFmsYgHQXatW
0f2XjrdmmWl4VfiekFKFDvGenxum9nEJrzIJOMm6qHnIiyCNA3xbMqmr7oqeIUa+
fQIDAQAB
-----END PUBLIC KEY-----
"""

let privateKey = """
-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDL8W1D9w5zHpmD
JqpTngIRJ+Sm21e42cRnTudhdejzKUiJQWkHSvQV5yC/+0iEXUsUJYEdSyrKhJFD
PT+IFGdjIiwb7IX+rUreWXlD/YYBL3/byMG4kYoO4oiPp2A+WvfeyLpuN549OXhk
7o5kXEZjKfjHTfmnAbCMoYW5BEpiHQC3HAeJZ5EiwAn8HZn5UY6lxJcf7H9hR83x
D0W7IZTNyxUu4aLNuihFIxJKgP/L/y95Y6ddZsyyHQopM43/7JOYBwufa07MWaxi
AdBdq1bR/ZeOt2aZaXhV+J6QUoUO8Z6fG6b2cQmvMgk4ybqoeciLII0DfFsyqavu
ip4hRr59AgMBAAECggEAUIw994XwMw922hG/W98gOd5jtHMVJnD73UGQqTGEm+VG
PM+Ux8iWtr/ec3Svo3elW4OkhwlVET9ikAf0u64zVzf769ty4K9YzpDQEEZlUrqL
6SZVPKxetppKDVKx9G7BT0BAQZ+947h7EIIXwxOeyTOeijkFzSwhqqlwwy4qoqzV
FTQS20QHE62hxzwuS5HBqw8ds183qAg9NbzR0Cp4za9qTiBB6C8KEcLqeatO+q+d
VCDsJcAMZOvW14N6BozKgbQ/WXZQ/3kNUPBndZLzzqaILFNmB1Zf2DVVJ9gU7+EK
xOac60StIfG81NllCTBrmRVq8yitNqwmutHMlxrIkQKBgQDvp39MkEHtNunFGkI5
R8IB5BZjtx5OdRBKkmPasmNU8U0XoQAJUKY/9piIpCtRi87tMXv8WWmlbULi66pu
4BnMIisw78xlIWRZTSizFrkFcEoVgEnbZBtSrOg/J5PAcjLEGCQoAdmMXAekR2/m
htv7FPijHPNUjyIFLaxwjl9izwKBgQDZ2mQeKNRHjIb5ZBzB0ZCvUy2y4+kaLrhZ
+CWMN1flL4dd1KuZKvCEfHY9kWOjqw6XneN4yT0aPmbBft4fihiiNW0Sm8i+fSpy
g0klw2HJl49wnwctBpRgTdMKGo9n14OGeu0xKOAy7I4j1tKrUXiRWnP9R583Ti7c
w7YHgdHM8wKBgEV147SaPzF08A6bzMPzY2zO4hpmsdcFoQIsKdryR04QXkrR9EO+
52C0pYM9Kf0Jq6Ed7ZS3iaJT58YDjjNyqqd648/cQP6yzfYAIiK+HERSRnay5zU6
b5zn1qyvWOi3cLVbVedumdJPvjtEJU/ImKvOaT5FntVMYwzjLw60hTsLAoGAZJnt
UeAY51GFovUQMpDL96q5l7qXknewuhtVe4KzHCrun+3tsDWcDBJNp/DTymjbvDg1
KzoC9XOLkB8+A+KJrZ5uWAGImi7Cw07NIJsxNR7AJonJjolTS4Wkxy2su49SNW/e
yKzPm7SRjwtNDb/5pWXX2kaQx8Fa8qeOD7lrYPECgYAwQ6o0vYmr+L1tOZZgMVv9
Jusa8beVUH5hyduJjmxbYOtFTkggAozdx7rs4BgyRsmDlV48cEmcVf/7IH4gMJLb
O+bbERwCYUChe+piANhnwfwDHzbRd8mmQus54P06X7bWu6Rmi7gbQGVN/Z6VhbIm
D2cOo0w4bk/3yb01xz1MEw==
-----END PRIVATE KEY-----
"""

extension String {
    var urlDecoded: String {
        var result = replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
        result.append(String(repeating: "=", count: (4 - (result.count & 3)) & 3))
        return result
    }

    var urlDecodedData: Data? {
        Data(base64Encoded: urlDecoded)
    }

    var urlDecodedBigUInt: BigUInt? {
        guard let data = urlDecodedData else { return nil }
        return BigUInt(data)
    }
}
