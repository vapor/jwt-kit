import Benchmark
import Foundation
import JWTKit

let benchmarks = {
    Benchmark.defaultConfiguration = .init(
        metrics: [.peakMemoryResident, .mallocCountTotal],
        thresholds: [
            .peakMemoryResident: .init(
                /// Tolerate up to 4% of difference compared to the threshold.
                relative: [.p90: 4],
                /// Tolerate up to one million bytes of difference compared to the threshold.
                absolute: [.p90: 1_100_000]
            ),
            .mallocCountTotal: .init(
                /// Tolerate up to 1% of difference compared to the threshold.
                relative: [.p90: 1],
                /// Tolerate up to 2 malloc calls of difference compared to the threshold.
                absolute: [.p90: 2]
            ),
        ]
    )

    Benchmark("ES256 Generated") { benchmark in
        for _ in benchmark.scaledIterations {
            let key = ES256PrivateKey()
            let keyCollection = JWTKeyCollection()
            keyCollection.add(ecdsa: key)
            let token = try await keyCollection.sign(payload)
            _ = try await keyCollection.verify(token, as: Payload.self)
        }
    }

    Benchmark("ES256 PEM") { benchmark in
        for _ in benchmark.scaledIterations {
            let key = try ES256PrivateKey(pem: ecdsaPrivateKey)
            let keyCollection = JWTKeyCollection()
            keyCollection.add(ecdsa: key)
            let token = try await keyCollection.sign(payload)
            _ = try await keyCollection.verify(token, as: Payload.self)
        }
    }

    Benchmark("RSA PEM") { benchmark in
        for _ in benchmark.scaledIterations {
            let key = try Insecure.RSA.PrivateKey(pem: rsaPrivateKey)
            let keyCollection = JWTKeyCollection()
            keyCollection.add(rsa: key, digestAlgorithm: .sha256)
            let token = try await keyCollection.sign(payload)
            _ = try await keyCollection.verify(token, as: Payload.self)
        }
    }

    Benchmark("EdDSA Generated") { benchmark in
        for _ in benchmark.scaledIterations {
            let key = try EdDSA.PrivateKey()
            let keyCollection = JWTKeyCollection()
            keyCollection.add(eddsa: key)
            let token = try await keyCollection.sign(payload)
            _ = try await keyCollection.verify(token, as: Payload.self)
        }
    }

    Benchmark("EdDSA Coordinates") { benchmark in
        for _ in benchmark.scaledIterations {
            let key = try EdDSA.PrivateKey(d: eddsaPrivateKeyBase64Url, curve: .ed25519)
            let keyCollection = JWTKeyCollection()
            keyCollection.add(eddsa: key)
            let token = try await keyCollection.sign(payload)
            _ = try await keyCollection.verify(token, as: Payload.self)
        }
    }
}

struct Payload: JWTPayload {
    let name: String
    let admin: Bool

    func verify(using signer: some JWTAlgorithm) async throws {
        // nothing to verify
    }
}

let payload = Payload(name: "Kyle", admin: true)

let ecdsaPrivateKey = """
    -----BEGIN PRIVATE KEY-----
    MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg2sD+kukkA8GZUpmm
    jRa4fJ9Xa/JnIG4Hpi7tNO66+OGgCgYIKoZIzj0DAQehRANCAATZp0yt0btpR9kf
    ntp4oUUzTV0+eTELXxJxFvhnqmgwGAm1iVW132XLrdRG/ntlbQ1yzUuJkHtYBNve
    y+77Vzsd
    -----END PRIVATE KEY-----
    """

let rsaPrivateKey = """
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

let eddsaPublicKeyBase64Url = "0ZcEvMCSYqSwR8XIkxOoaYjRQSAO8frTMSCpNbUl4lE"
let eddsaPrivateKeyBase64Url = "d1H3_dcg0V3XyAuZW2TE5Z3rhY20M-4YAfYu_HUQd8w"
