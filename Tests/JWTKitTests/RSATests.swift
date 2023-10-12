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

    func testGCDCalculation() throws {
        let testsDirectory: String = URL(fileURLWithPath: "\(#filePath)").pathComponents.dropLast(1).joined(separator: "/")
        let url = URL(fileURLWithPath: "\(testsDirectory)/TestVectors/gcd_test.json")
        guard let data = try? Data(contentsOf: url) else {
            return XCTFail("Failed to load greatest common divisor test vectors from file gcd_test.json")
        }

        let testVectors = try JSONDecoder().decode([GCDTestVector].self, from: data)

        for testVector in testVectors {
            guard
                let a = BigUInt(testVector.a, radix: 16),
                let b = BigUInt(testVector.b, radix: 16),
                let gcd = BigUInt(testVector.gcd, radix: 16)
            else {
                return XCTFail("Failed to extract or parse test vector")
            }

            XCTAssertEqual(a.gcd(with: b), gcd, "The greatest common divisor of \(a) and \(b) should equal \(gcd)")
        }
    }

    func testRSACertificate() throws {
        let test = TestPayload(
            subject: "JWTKit",
            expiration: .init(value: .distantFuture),
            admin: true
        )

        let jwt = try JWTSigner.rs256(
            key: .private(pem: certPrivateKey)
        ).sign(test)

        let payload = try JWTSigner.rs256(
            key: .certificate(pem: cert)
        ).verify(jwt, as: TestPayload.self)
        XCTAssertEqual(payload, test)
    }

    func testKeySizeTooSmall() throws {
        XCTAssertThrowsError(try JWTSigner.rs256(key: .private(pem: _512BytesKey)))
    }

    // MARK: Private functions

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

let _512BytesKey = """
-----BEGIN PRIVATE KEY-----
MIIBVAIBADANBgkqhkiG9w0BAQEFAASCAT4wggE6AgEAAkEAtgeOpWeiRIq0Blbc
qq4P7sKnyDmj1mpQq7OyRKZM0qbwyyMM5Nisf5Y+RSDM7JDwqMeLspGo5znLBzN5
L14JIQIDAQABAkBlMWRSfX9O3VDhKU65L9S5pcsCW1DCdQ3tthMHaO/SNn4jhmbf
MamrK4TWctjuau+CwUtQz/kS/fjveYBSVklVAiEA2r1fExLdTwo1pRzCqvUhq7MO
4wu1dPvv8mJZZvGxQGMCIQDVCVsmeiN+s9erwd95wUZKb4zBkT6MQC0r1fGQBnEN
qwIgBBT6nDmC5cG0BJPH0jbm3PRnd7c1OKym6qgJMRGblC8CICh9Zr2haS2jsNIM
PxU9DscG/JGtsV2mtO8n8omVL9eRAiEA1ccs/gJCMAwJ/jeA8tZwOF3GEb/9tGow
RR8+JsDsJY8=
-----END PRIVATE KEY-----
"""

let certPrivateKey = """
-----BEGIN PRIVATE KEY-----
MIIEwAIBADANBgkqhkiG9w0BAQEFAASCBKowggSmAgEAAoIBAQC9hpMHhjS6UX5G
k5so60/p+J2xDgiOw/1Kgp33t+oTJ1SnYUwp3CSUQ8y5cPNQGdQ4yequ1UwPW9uR
A4zNEzeEFIMGWOiC0S7p74ryuYTWg4HMqxed4q0Zt3KVFq/MbsZYwvb88ksbtZ9+
unccIEeg/loxfsX7aJkFgl58Nz8KtLcO3LreP0ySbxBwWrN3TTtAWej2ofo39viR
uxUJxWmpEHySc+ioSJLHxCG2iuxR+BMGieHtGQ7Ri0K0f1RlLwRlhQfZrhGIarqr
Mw2plcyVFUfAptOD3jmkzHmy7VrNfeyOEpj2roiCLq2NqC+Gf7N+fLPMj3w28kCj
x3ZEk2ZRAgMBAAECggEBAIgNQSLXnqZZtfJoJ6waMAXfqSPe1RnXa86/MTMQ3YHe
bBCz8f7iv4eHnEFK6f+IayZRHJ1hFPa5lEbna34T23h/WQeHb3HpRGo+wVo4/zkW
smkAMTXv8R9S53hLDuwMYWp6mt8999juao6IwNR5/7F8pbZ+MRWnIqIn0jgNWL4P
evDtOaxDGW7FYVU8ew44xjBl6tpCKOvDYxKJ/Ze4FW0XQPj8P+rbA8DeCSmEZb63
Y7ZDwgw6y6rf5aDqNAo3g1Gur7kpPhOrbGzr2b9RXiSSPIJyRMXF4I6qJ4q/MUXR
0oL4TaiCwvx/m6g5nyG3hx7VbXpl1BMBhfYqqLqcAzkCgYEA8dZslkCqS6a84miR
5HbUpl6xYwrra/sy5LwI82QrU/rYlOxU6JXCimOI+VMlV+hrgmPb3nYA9YR3byvr
yTj+M45g3UJvzsYcBEdsQsgP8gxeohDEsGKkeQ/GHrGiV/bxh8fDpMRxDDD15yaP
MCVEy4CUIwjnG0b7N4pc3WaNEmsCgYEAyJ/myS3+qwAY3vOQm30rQYAt0l9kvfAV
N2EAvQZJtS+PCJcg6/GY90BiPQOQVQCIfg9kf1XPN1cBTP5ty9vSigeBUSDSBd/v
AdQesMnCYHMCwb1XYjfWPJRmj0296dAI0RlwXz9fpmUUd/WPQWCxeLjwq+3a0ZJO
8WBIa3Tm8TMCgYEAhI8nWDi739nWgTgWeCeWqlcPXp22q6q2m+Bh+5+1jEPcgc0F
QbQNPbQPebLUrlnszD0WYNtH7Uwd92cYyGSgGfx6Je3rwWigJMxNkFF/RAr5uFX+
qjx3sRAvZdWyigsHG4kpOWCgIrGXqItfQ2G6Ut341TdlDnOa8je6bXVv8F8CgYEA
wPJv7anrlB/qy3lp6PCPilYxO3L9G2LrtK/5GtIST0vm/vcB9YkMeTaVhGKKDAYQ
P1SkbYZkXK+zk43aoMXQDWm8Z/7tnjLI1XRg89uGsmXKD/P+N3rF8ssye73j2Rt3
b0pM9X2oiwoJjnk/BjxtUlJjPKbr3MQeYiwcWiQ6+1sCgYEAzqcM2JFGpY3P5TnV
LD3Jb4zewqGbgJ5T2qLD/cJYDzskQos+Y2vojbh1wswsBwFh/RyIzuf3+yfvUT4+
EA5DyKDppexIsWXavQ7718i/OSFPCOcWP/vfu5Mr5S/CQcbFbHxiBSa2ZmDD/VXr
5T9BDCRf/HiTZpuyRcLStfOquYk=
-----END PRIVATE KEY-----
"""

let cert = """
-----BEGIN CERTIFICATE-----
MIICljCCAX4CCQDNA8gK8Kol/DANBgkqhkiG9w0BAQsFADANMQswCQYDVQQGEwJJ
VDAeFw0yMzEwMTIxNDEzMzVaFw0yMzExMTExNDEzMzVaMA0xCzAJBgNVBAYTAklU
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAvYaTB4Y0ulF+RpObKOtP
6fidsQ4IjsP9SoKd97fqEydUp2FMKdwklEPMuXDzUBnUOMnqrtVMD1vbkQOMzRM3
hBSDBljogtEu6e+K8rmE1oOBzKsXneKtGbdylRavzG7GWML2/PJLG7Wffrp3HCBH
oP5aMX7F+2iZBYJefDc/CrS3Dty63j9Mkm8QcFqzd007QFno9qH6N/b4kbsVCcVp
qRB8knPoqEiSx8QhtorsUfgTBonh7RkO0YtCtH9UZS8EZYUH2a4RiGq6qzMNqZXM
lRVHwKbTg945pMx5su1azX3sjhKY9q6Igi6tjagvhn+zfnyzzI98NvJAo8d2RJNm
UQIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQAMEYdPGEik0I6gfrAZ1096kJWODyt+
SEc6KLxFKTWPXoy8QjuYazxrf7oNXF0ZxqUzv42AfyQR3sFYNHf9CAFv+oBav1Q9
MHPVpBn+DE092fvU2cRHhmbJFJaRPARxsonNeFwczJPOuseNSbjA65K4Bqlm9ywv
7p5F+TqI080mpeMMw/KA1VcIqxbJLO7IUDg9w25XotTBgplFh/SCE5FgWB0g2Iff
la4Op9AHh7N6hiTGJwn6MyxfxFm8+2wATNX3BglUXwiPtfMwGnNy4ft5Nxi6ZI7m
QkJUDkYq0ZsPjk6/4fYP1abrsDcWua0BrYtzBZqLVWKQWJ0xftGmX2m6
-----END CERTIFICATE-----
"""

struct GCDTestVector: Codable {
    let a: String
    let b: String
    let lcm: String
    let gcd: String
}

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
