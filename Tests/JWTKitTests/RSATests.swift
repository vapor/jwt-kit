#if canImport(Testing)
import Testing
import JWTKit
import _CryptoExtras

@Suite("RSA Tests")
struct RSATests {
    @Test("Test RSA docs")
    func rsaDocs() async throws {
        await #expect(throws: Never.self) {
            try await JWTKeyCollection().add(rsa: Insecure.RSA.PublicKey(pem: publicKey), digestAlgorithm: .sha256)
        }
    }

    @Test("Test private key init")
    func privateKeyInit() async throws {
        #expect(throws: Never.self) {
            try Insecure.RSA.PrivateKey(modulus: modulus, exponent: publicExponent, privateExponent: privateExponent)
        }
    }

    @Test("Test public key init")
    func publicKeyInit() async throws {
        #expect(throws: Never.self) {
            try Insecure.RSA.PublicKey(modulus: modulus, exponent: publicExponent)
        }
    }

    @Test("Test private key init from primes")
    func privateKeyInitFromPrimes() async throws {
        #expect(throws: Never.self) {
            try Insecure.RSA.PrivateKey(
                modulus: modulus,
                exponent: publicExponent,
                privateExponent: privateExponent,
                prime1: prime1,
                prime2: prime2
            )
        }
    }

    @Test("Test public key init from SwiftCrypto key")
    func publicKeyInitFromSwiftCryptoKey() async throws {
        let cryptoKey = try _RSA.Signing.PublicKey(pemRepresentation: publicKey)
        let jwtKey = try Insecure.RSA.PublicKey(backing: cryptoKey)
        let otherKey = try Insecure.RSA.PublicKey(pem: publicKey)
        #expect(jwtKey == otherKey)
    }

    @Test("Test private key init from SwiftCrypto key")
    func privateKeyInitFromSwiftCryptoKey() async throws {
        let cryptoKey = try _RSA.Signing.PrivateKey(pemRepresentation: privateKey)
        let jwtKey = try Insecure.RSA.PrivateKey(backing: cryptoKey)
        let otherKey = try Insecure.RSA.PrivateKey(pem: privateKey)
        #expect(jwtKey == otherKey)
    }

    @Test("Test Signing with Private Key")
    func sign() async throws {
        let keyCollection = try await JWTKeyCollection()
            .add(rsa: Insecure.RSA.PrivateKey(pem: privateKey), digestAlgorithm: .sha256, kid: "private")

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: true,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let token = try await keyCollection.sign(payload, kid: "private")
        let verifiedPayload = try await keyCollection.verify(token, as: TestPayload.self)
        #expect(verifiedPayload == payload)
    }

    @Test("Test Signing with Public Key Should Fail")
    func signWithPublic() async throws {
        let keyCollection = try await JWTKeyCollection()
            .add(rsa: Insecure.RSA.PublicKey(pem: publicKey), digestAlgorithm: .sha256, kid: "public")

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: true,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        await #expect(throws: JWTError.self) {
            _ = try await keyCollection.sign(payload, kid: "private")
        }
    }

    @Test("Test signing with raw built private key")
    func signWithRawPrivateKey() async throws {
        let privateKey = try Insecure.RSA.PrivateKey(
            modulus: modulus,
            exponent: publicExponent,
            privateExponent: privateExponent
        )

        let keyCollection = try await JWTKeyCollection()
            .add(
                rsa: Insecure.RSA.PrivateKey(pem: privateKey.pemRepresentation),
                digestAlgorithm: .sha256,
                kid: "private"
            )

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: true,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let token = try await keyCollection.sign(payload)
        let verifiedPayload = try await keyCollection.verify(token, as: TestPayload.self)
        #expect(verifiedPayload == payload)
    }

    @Test("Test signing with raw built private key with primes")
    func signWithRawPrivateKeyWithPrimes() async throws {
        let privateKey = try Insecure.RSA.PrivateKey(
            modulus: modulus,
            exponent: publicExponent,
            privateExponent: privateExponent,
            prime1: prime1,
            prime2: prime2
        )

        let keyCollection = try await JWTKeyCollection()
            .add(
                rsa: Insecure.RSA.PrivateKey(pem: privateKey.pemRepresentation),
                digestAlgorithm: .sha256,
                kid: "private"
            )

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: true,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let token = try await keyCollection.sign(payload)
        let verifiedPayload = try await keyCollection.verify(token, as: TestPayload.self)
        #expect(verifiedPayload == payload)
    }

    @Test("Test get public key primitives")
    func getPublicKeyPrimitives() async throws {
        let publicKey = try Insecure.RSA.PublicKey(modulus: modulus, exponent: publicExponent)
        let (keyModulus, keyExponent) = try publicKey.getKeyPrimitives()
        #expect(keyModulus == modulus.base64URLDecodedData())
        #expect(keyExponent == publicExponent.base64URLDecodedData())
    }

    @Test("Test RSA Certificate verification")
    func verifyWithCertificate() async throws {
        let test = TestPayload(
            sub: "vapor",
            name: "foo",
            admin: true,
            exp: .init(value: .distantFuture)
        )
        let signerCollection = try await JWTKeyCollection()
            .add(rsa: Insecure.RSA.PrivateKey(pem: certPrivateKey), digestAlgorithm: .sha256, kid: "private")

        let jwt = try await signerCollection.sign(test, kid: "private")

        let verifierCollection = try await JWTKeyCollection()
            .add(rsa: Insecure.RSA.PublicKey(certificatePEM: cert), digestAlgorithm: .sha256, kid: "cert")

        let payload = try await verifierCollection.verify(jwt, as: TestPayload.self)
        #expect(payload == test)
    }

    @Test("Test adding a too small key")
    func addTooSmallKey() async throws {
        await #expect(throws: (any Error).self) {
            try await JWTKeyCollection().add(rsa: Insecure.RSA.PrivateKey(pem: _512BytesKey), digestAlgorithm: .sha256)
        }
    }

    @Test("Test RS256 verification")
    func verifyRS256() async throws {
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
            .add(rsa: Insecure.RSA.PublicKey(pem: publicKey2), digestAlgorithm: .sha256, kid: "public")

        let payload = try await keyCollection.verify(token, as: TestPayload.self)
        #expect(payload == testPayload)
    }

    @Test("Test exporting public key as PEM")
    func exportPublicKeyAsPEM() async throws {
        let key = try Insecure.RSA.PublicKey(pem: publicKey)
        let key2 = try Insecure.RSA.PublicKey(pem: key.pemRepresentation)
        #expect(key == key2)
    }

    @Test("Test exporting private key as PEM")
    func exportPrivateKeyAsPEM() async throws {
        let key = try Insecure.RSA.PrivateKey(pem: privateKey)
        let key2 = try Insecure.RSA.PrivateKey(pem: key.pemRepresentation)
        #expect(key == key2)
    }

    @Test("Test exporting public key from private key")
    func exportPublicKeyWhenKeyIsPrivate() async throws {
        let privateKey = try Insecure.RSA.PrivateKey(pem: privateKey)
        let publicKeyFromPrivate = try Insecure.RSA.PublicKey(pem: privateKey.publicKey.pemRepresentation)
        let publicKey = try Insecure.RSA.PublicKey(pem: publicKey)
        #expect(publicKeyFromPrivate == publicKey)
    }

    @Test("Test exporting raw built private key as PEM")
    func exportKeyAsPEMWhenRawBuilt() async throws {
        let key = try Insecure.RSA.PrivateKey(
            modulus: modulus,
            exponent: publicExponent,
            privateExponent: privateExponent
        )
        let key2 = try Insecure.RSA.PrivateKey(pem: key.pemRepresentation)
        #expect(key == key2)
    }
}

let modulus = """
    vTHHoCaR0tlYfvapRv94hUTMrdSymIrWIIZ5Kmv5bIYWtK0TMX0icLkB0PzR2IDLj1L7hzBKUljBGzjf6ujfZwru5-odDZ344A6AhH5B5Zie1ALUTnizD-8XtWcdOtv4aF5NwgRJns0YY-HVr_KKfPZurfMf7JI2wSCt0TRRUixkfJgypnLNZNMowcMiGD9GYdCb2mC43V8DKNpUIIIUJK_auxqAxdEnY6GwI4zYnQdCv8ULai_LcB2CQhj5gm9PeKI6K1qkKs5_F1N2-2y9srrSk7pYPU0xxrj5Ap5GsTaJJJhV9QV1bgDiJaakWhh2m9jSs6SsufHCPT5RiCVh5Q
    """

let publicExponent = "AQAB"

let privateExponent = """
    B0fVIMqbLfwDNc-UMBFAuBAvuDjJLqmZF-NU4lcJYC3Aze8jH_Jq0t-rvDkecjBypO9Skp8_HPAhbkTACTAw-KwpCW-u8okzvJuSQocBTi6TXiFFvkdSzLgst2RicZNpecq3P1Ie6yeFWsKkEINK5Qguti72-Yme5cu2JKjYwEq37c94_hNdD4CPY7XebgcXeb8dnqr40--WVIbyxSYl5uV6ZRx7vQGXyZwFezhgoyYMhkoRs88iukTeOjs_MRfmTr-akfYm67Pzwm0bC7gHU0aNS_apl7KDNfIO2MOE11WDYKmul1VmH6N0mEaxdOa_Mw5S0JlB9szX3lAEd5-buQ
    """

let prime1 = """
    _j0jjTdqOFbZWS_UlhwXp_sPo51ELp3yLn7aEVxkjFy3ON-J6pLYN4VY0NnBzz2L_3QNN0OgFApqdSPpF2wpU7LBHX9EaRz4vsKzT7WcZJU1mDMZSIEYwDEYrnRF5w30Zs6YZxJg8F1QaM53fal-K6hHeUkFAM60_39izsqaFH8
    """

let prime2 = """
    voFK8mvzwnEVvHWV0NEqGvdxP-yod65ubYWIJe2j0ZJwR3T0Lhrhtn8XOejEWgR2OIBw-lRbfMlrikQAO8jQf95z9bzdGCaDldzChCtQI_8Us1I4Jge3F5peozCED8RQRdhuCsxP6xNfCrm3zmuOtfWldfKiqN4pnA0_UG30h5s
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
#endif  // canImport(Testing)
