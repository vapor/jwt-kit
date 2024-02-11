import BigInt
import JWTKit
import XCTest

final class RSATests: XCTestCase {
    func testCalculatePrimeFactors() throws {
        try wycheproof(fileName: "rsa_oaep_2048_sha1_mgf1sha1_test", testFunction: testPrimeFactors)
        try wycheproof(fileName: "rsa_oaep_2048_sha224_mgf1sha1_test", testFunction: testPrimeFactors)
        try wycheproof(fileName: "rsa_oaep_2048_sha256_mgf1sha256_test", testFunction: testPrimeFactors)
    }

    func testRSADocs() async throws {
        await XCTAssertNoThrowAsync(try await JWTKeyCollection().addRS256(key: Insecure.RSA.PublicKey(pem: publicKey)))
    }

    func testPrivateKeyInitialization() throws {
        XCTAssertNoThrow(try Insecure.RSA.PrivateKey(modulus: modulus, exponent: publicExponent, privateExponent: privateExponent))
    }

    func testPublicKeyInitialization() throws {
        XCTAssertNoThrow(try Insecure.RSA.PublicKey(modulus: modulus, exponent: publicExponent))
    }

    func testSigning() async throws {
        let keyCollection = try await JWTKeyCollection()
            .addRS256(key: Insecure.RSA.PrivateKey(pem: privateKey), kid: "private")
            .addRS256(key: Insecure.RSA.PublicKey(pem: publicKey), kid: "public")

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let privateSigned = try await keyCollection.sign(payload, header: ["kid": "private"])
        try await XCTAssertEqualAsync(await keyCollection.verify(privateSigned, as: TestPayload.self), payload)
    }

    func testSigningWithPublic() async throws {
        let keyCollection = try await JWTKeyCollection()
            .addRS256(key: Insecure.RSA.PublicKey(pem: publicKey), kid: "public")

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        await XCTAssertThrowsErrorAsync(_ = try await keyCollection.sign(payload))
    }

    func testSigningWithRawBuiltPrivateKey() async throws {
        let privateKey = try Insecure.RSA.PrivateKey(modulus: modulus, exponent: publicExponent, privateExponent: privateExponent)

        let keyCollection = try await JWTKeyCollection()
            .addRS256(key: Insecure.RSA.PrivateKey(pem: privateKey.pemRepresentation), kid: "private")
            .addRS256(key: Insecure.RSA.PublicKey(pem: privateKey.publicKey.pemRepresentation), kid: "public")

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let privateSigned = try await keyCollection.sign(payload)
        try await XCTAssertEqualAsync(await keyCollection.verify(privateSigned, as: TestPayload.self), payload)
        try await XCTAssertEqualAsync(await keyCollection.verify(privateSigned, as: TestPayload.self), payload)
    }

    func testGetPublicKeyPrimitives() async throws {
        let publicKey = try Insecure.RSA.PublicKey(modulus: modulus, exponent: publicExponent)
        let (keyModulus, exponent) = try publicKey.getKeyPrimitives()
        XCTAssertEqual(keyModulus, modulus)
        XCTAssertEqual(exponent, publicExponent)
    }

    func testGetPrivateKeyPrimitives() async throws {
        let privateKey = try Insecure.RSA.PrivateKey(modulus: modulus, exponent: publicExponent, privateExponent: privateExponent)
        let (keyModulus, exponent, keyPrivateExponent) = try privateKey.getKeyPrimitives()
        XCTAssertEqual(keyModulus, modulus)
        XCTAssertEqual(exponent, publicExponent)
        XCTAssertEqual(keyPrivateExponent, privateExponent)
    }

    func testGetPrivateKeyPrimitivesFromNonRawBuiltKey() async throws {
        let privateKey = try Insecure.RSA.PrivateKey(pem: """
        -----BEGIN RSA PRIVATE KEY-----
        MIIEowIBAAKCAQEAgWu7yhI35FScdKARYboJoAm+T7yJfJ9JTvAok/RKOJYcL8oL\nIRSeLqQX83PPZiWdKTdXaiGWntpDu6vW7VAb+HWPF6tNYSLKDSmR3sEu2488ibWi
        jZtNTCKOSb/1iAKAI5BJ80LTqyQtqaKzT0XUBtMsde8vX1nKI05UxujfTX3kqUtk\nZgLv1Yk1ZDpUoLOWUTtCm68zpjtBrPiN8bU2jqCGFyMyyXys31xFRzz4MyJ5tREH
        kQCzx0g7AvW0ge/sBTPQ2U6NSkcZvQyDbfDv27cMUHij1Sjx16SY9a2naTuOgamj\ntUzyClPLVpchX+McNyS0tjdxWY/yRL9MYuw4AQIDAQABAoIBAC+M9Lc+0FhNGhrj
        gN9mKgkp60mCnQUzxQyCwnXx6J83z+1jD4m8+I1sbvxczZPbOA4frjdpVdzRltdK\nQLJ6n3w/PS7WGp0Y2iHR5y1vzxaOXxC9spbSu6jAfYTtSXoKaSgn6HO/VuPna/uK
        stTqdAd56Tj/g2lGJTWpnw5iG0Ft9lCnic3RiJ/v68qwU+4UFuv7hy0tlRTz5NKz\nZDzymWKDWqhpydHmhRRfnRcIk4VyKT8/vncUwC/MWH9u+a4xvAvZYemsDnyUiHVz
        FbkCE1n+thNJkkD0dvttfW0oTCq4g2HGC209wSRIDpEQQRxrh6PUeUzdvfGp8Wal\ndbuY7VECgYEA+kVqK0URfwbZGEnO8JnagCunkOKgqAqv+I44/lmZwmj/Z9uvFXRo
        5TQNwpSNuYB9V5ujpoVgJaJ4BWUCnD/uwqNwlqcQydsXzB3u4GKI5jZrpCN8i7+s\nhP9UuV1pfU8+n3VuWkIhfrHEmSgn7+AhCkzETho2qPvfv7u8bxou4DUCgYEAhGIj
        QyEZWORJI2FJ+APp146v/nndXwCGIbPCbp8rHFFL4dYQsgJI6tGQDMO9xcMoz0jt\n/lJTUu4hBIL7jm1S/bYez6JqlbjUhNpvSUp/M0SWlS36LLQqrc49IZ8H7AXjDiG5
        az6zVHMtz8CJY0/YT5CUjDszhN8u56vdAEBHyh0CgYEAwwhVNGMev18Wz1a1bcp3\n/GoIq1/w0wOBHrG2uIAa0uYAI2+Pgai2Fef60SfzShxXkW44mgxWYP27initEBbC
        eevkUYLgEm4qnWa2QSaIiN7gA4mkBUPZrctMuyeQjZaztpBM7wmaEKF4E+K3PLft\nB5nLYRIMhqPCOiiTMAG3hgECgYAyI00BnqaP8R32JWGzaiAFgMgNFDCQS42BdCh+
        ZxAX0H5x0PZPxOfC742kF/pmzQxGvXNNr/ZY4VFl+Qm3Hpag+nne37+IZxEuI+Ck\nHG/iheaWJ2ypw66qVwL2GdoRPQWKk6E7Ces3X8wI8/3UvCfLspFgLwfLGhAUtBWm
        g7HszQKBgEGa1OX9PQFrOojSizXK2jcalVJLiy01+cJZB1ZqIwFAYG9VTEOo3IrH\nhUGJzX0PZGGW8+r+S50ORYlJ7hl0xGZrcnAv4ftONtYN4GmB7t/QKheShWTX0Q+C
        eGwWRyV8jo3G+nJDtGEb3MTHVXPK3hviJRXDHHGhw+sh+JdL49x4
        -----END RSA PRIVATE KEY-----
        """)
        let (keyModulus, exponent, keyPrivateExponent) = try privateKey.getKeyPrimitives()
        XCTAssertEqual(keyModulus, modulus)
        XCTAssertEqual(exponent, publicExponent)
        XCTAssertEqual(keyPrivateExponent, privateExponent)
    }

    func testRSACertificate() async throws {
        let test = TestPayload(
            sub: "vapor",
            name: "foo",
            admin: true,
            exp: .init(value: .distantFuture)
        )
        let keyCollection = try await JWTKeyCollection()
            .addRS256(key: Insecure.RSA.PrivateKey(pem: certPrivateKey), kid: "private")
            .addRS256(key: Insecure.RSA.PublicKey(certificatePEM: cert), kid: "cert")

        let jwt = try await keyCollection.sign(test, header: ["kid": "private"])
        let payload = try await keyCollection.verify(jwt, as: TestPayload.self)
        XCTAssertEqual(payload, test)
    }

    func testKeySizeTooSmall() async throws {
        await XCTAssertThrowsErrorAsync(try await JWTKeyCollection().addRS256(key: Insecure.RSA.PrivateKey(pem: _512BytesKey)))
    }

    func testRS256Verification() async throws {
        let token = """
        eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YXBvciIsIm5hbWUiOiJmb28iLCJhZG1pbiI6dHJ1ZSwiZXhwIjoyMDAwMDAwMDAwfQ.JZ3uuzojbqbkZBoCKOrjzu4ICNjFt_H4XNqO4I8sM8PRmxzg-_kY2_MhVJkKga30afWp00z5FNoT14CsdKXWKEaWCwXgYTatLQI3yt77aqj7-RC_eBCl6qRDnPH7Aq5KkBNGsoMwUAWKeHB7ZHZulqqqaeRUyEIXmUJiyUy7TjZyVhk1WsXANGxDWvutsVG6dmiFhaSWqj1RsmyWqbuDoyd3uIHzyHy4mx1Y-nwxMofoS0k-SkyZcEPVJ2Am99VZ4rwSJbH2QcmaZr5o1rS8sJiReVYfyEF2YghN9tLj3FF11scgtpjDMzcIkbsIntclaYmU1b7GlIFB6897sdjJpA
        """
        let testPayload = TestPayload(
            sub: "vapor",
            name: "foo",
            admin: true,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let keyCollection = try await JWTKeyCollection()
            .addRS256(key: Insecure.RSA.PrivateKey(pem: privateKey2), kid: "private")
            .addRS256(key: Insecure.RSA.PublicKey(pem: publicKey2), kid: "public")

        let payload = try await keyCollection.verify(token, as: TestPayload.self)
        XCTAssertEqual(payload, testPayload)
    }

    func testExportPublicKeyAsPEM() async throws {
        let key = try Insecure.RSA.PublicKey(pem: publicKey)
        let key2 = try Insecure.RSA.PublicKey(pem: key.pemRepresentation)
        XCTAssertEqual(key, key2)
    }

    func testExportPrivateKeyAsPEM() async throws {
        let key = try Insecure.RSA.PrivateKey(pem: privateKey)
        let key2 = try Insecure.RSA.PrivateKey(pem: key.pemRepresentation)
        XCTAssertEqual(key, key2)
    }

    func testExportPublicKeyWhenKeyIsPrivate() async throws {
        let privateKey = try Insecure.RSA.PrivateKey(pem: privateKey)
        let publicKeyFromPrivate = try Insecure.RSA.PublicKey(pem: privateKey.publicKey.pemRepresentation)
        let publicKey = try Insecure.RSA.PublicKey(pem: publicKey)
        XCTAssertEqual(publicKeyFromPrivate, publicKey)
    }

    func testExportKeyAsPEMWhenRawBuilt() async throws {
        let key = try Insecure.RSA.PrivateKey(modulus: modulus, exponent: publicExponent, privateExponent: privateExponent)
        let key2 = try Insecure.RSA.PrivateKey(pem: key.pemRepresentation)
        XCTAssertEqual(key, key2)
    }

    let modulus = """
    gWu7yhI35FScdKARYboJoAm-T7yJfJ9JTvAok_RKOJYcL8oLIRSeLqQX83PPZiWdKTdXaiGWntpDu6vW7VAb-HWPF6tNYSLKDSmR3sEu2488ibWijZtNTCKOSb_1iAKAI5BJ80LTqyQtqaKzT0XUBtMsde8vX1nKI05UxujfTX3kqUtkZgLv1Yk1ZDpUoLOWUTtCm68zpjtBrPiN8bU2jqCGFyMyyXys31xFRzz4MyJ5tREHkQCzx0g7AvW0ge_sBTPQ2U6NSkcZvQyDbfDv27cMUHij1Sjx16SY9a2naTuOgamjtUzyClPLVpchX-McNyS0tjdxWY_yRL9MYuw4AQ
    """

    let publicExponent = "AQAB"

    let privateExponent = """
    L4z0tz7QWE0aGuOA32YqCSnrSYKdBTPFDILCdfHonzfP7WMPibz4jWxu_FzNk9s4Dh-uN2lV3NGW10pAsnqffD89LtYanRjaIdHnLW_PFo5fEL2yltK7qMB9hO1JegppKCfoc79W4-dr-4qy1Op0B3npOP-DaUYlNamfDmIbQW32UKeJzdGIn-_ryrBT7hQW6_uHLS2VFPPk0rNkPPKZYoNaqGnJ0eaFFF-dFwiThXIpPz--dxTAL8xYf275rjG8C9lh6awOfJSIdXMVuQITWf62E0mSQPR2-219bShMKriDYcYLbT3BJEgOkRBBHGuHo9R5TN298anxZqV1u5jtUQ
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

    let privateKey2 = """
    -----BEGIN PRIVATE KEY-----
    MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQC7VJTUt9Us8cKj
    MzEfYyjiWA4R4/M2bS1GB4t7NXp98C3SC6dVMvDuictGeurT8jNbvJZHtCSuYEvu
    NMoSfm76oqFvAp8Gy0iz5sxjZmSnXyCdPEovGhLa0VzMaQ8s+CLOyS56YyCFGeJZ
    qgtzJ6GR3eqoYSW9b9UMvkBpZODSctWSNGj3P7jRFDO5VoTwCQAWbFnOjDfH5Ulg
    p2PKSQnSJP3AJLQNFNe7br1XbrhV//eO+t51mIpGSDCUv3E0DDFcWDTH9cXDTTlR
    ZVEiR2BwpZOOkE/Z0/BVnhZYL71oZV34bKfWjQIt6V/isSMahdsAASACp4ZTGtwi
    VuNd9tybAgMBAAECggEBAKTmjaS6tkK8BlPXClTQ2vpz/N6uxDeS35mXpqasqskV
    laAidgg/sWqpjXDbXr93otIMLlWsM+X0CqMDgSXKejLS2jx4GDjI1ZTXg++0AMJ8
    sJ74pWzVDOfmCEQ/7wXs3+cbnXhKriO8Z036q92Qc1+N87SI38nkGa0ABH9CN83H
    mQqt4fB7UdHzuIRe/me2PGhIq5ZBzj6h3BpoPGzEP+x3l9YmK8t/1cN0pqI+dQwY
    dgfGjackLu/2qH80MCF7IyQaseZUOJyKrCLtSD/Iixv/hzDEUPfOCjFDgTpzf3cw
    ta8+oE4wHCo1iI1/4TlPkwmXx4qSXtmw4aQPz7IDQvECgYEA8KNThCO2gsC2I9PQ
    DM/8Cw0O983WCDY+oi+7JPiNAJwv5DYBqEZB1QYdj06YD16XlC/HAZMsMku1na2T
    N0driwenQQWzoev3g2S7gRDoS/FCJSI3jJ+kjgtaA7Qmzlgk1TxODN+G1H91HW7t
    0l7VnL27IWyYo2qRRK3jzxqUiPUCgYEAx0oQs2reBQGMVZnApD1jeq7n4MvNLcPv
    t8b/eU9iUv6Y4Mj0Suo/AU8lYZXm8ubbqAlwz2VSVunD2tOplHyMUrtCtObAfVDU
    AhCndKaA9gApgfb3xw1IKbuQ1u4IF1FJl3VtumfQn//LiH1B3rXhcdyo3/vIttEk
    48RakUKClU8CgYEAzV7W3COOlDDcQd935DdtKBFRAPRPAlspQUnzMi5eSHMD/ISL
    DY5IiQHbIH83D4bvXq0X7qQoSBSNP7Dvv3HYuqMhf0DaegrlBuJllFVVq9qPVRnK
    xt1Il2HgxOBvbhOT+9in1BzA+YJ99UzC85O0Qz06A+CmtHEy4aZ2kj5hHjECgYEA
    mNS4+A8Fkss8Js1RieK2LniBxMgmYml3pfVLKGnzmng7H2+cwPLhPIzIuwytXywh
    2bzbsYEfYx3EoEVgMEpPhoarQnYPukrJO4gwE2o5Te6T5mJSZGlQJQj9q4ZB2Dfz
    et6INsK0oG8XVGXSpQvQh3RUYekCZQkBBFcpqWpbIEsCgYAnM3DQf3FJoSnXaMhr
    VBIovic5l0xFkEHskAjFTevO86Fsz1C2aSeRKSqGFoOQ0tmJzBEs1R6KqnHInicD
    TQrKhArgLXX4v3CddjfTRJkFWDbE/CkvKZNOrcf1nhaGCPspRJj2KUkj1Fhl9Cnc
    dn/RsYEONbwQSjIfMPkvxF+8HQ==
    -----END PRIVATE KEY-----
    """

    let publicKey2 = """
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAu1SU1LfVLPHCozMxH2Mo
    4lgOEePzNm0tRgeLezV6ffAt0gunVTLw7onLRnrq0/IzW7yWR7QkrmBL7jTKEn5u
    +qKhbwKfBstIs+bMY2Zkp18gnTxKLxoS2tFczGkPLPgizskuemMghRniWaoLcyeh
    kd3qqGElvW/VDL5AaWTg0nLVkjRo9z+40RQzuVaE8AkAFmxZzow3x+VJYKdjykkJ
    0iT9wCS0DRTXu269V264Vf/3jvredZiKRkgwlL9xNAwxXFg0x/XFw005UWVRIkdg
    cKWTjpBP2dPwVZ4WWC+9aGVd+Gyn1o0CLelf4rEjGoXbAAEgAqeGUxrcIlbjXfbc
    mwIDAQAB
    -----END PUBLIC KEY-----
    """
}
