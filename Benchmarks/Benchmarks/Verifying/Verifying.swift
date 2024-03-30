import Benchmark
import Foundation
import JWTKit

let customThresholds = BenchmarkThresholds(
    relative: [.p25: 15.0, .p50: 15.0, .p75: 15.0, .p90: 15.0, .p99: 15.0],
    absolute: [:]
)

let benchmarks = {
    Benchmark(
        "ES256",
        configuration: .init(
            thresholds: [.peakMemoryResident: customThresholds]
        )
    ) { benchmark in
        let pem = """
        -----BEGIN PUBLIC KEY-----
        MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
        q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
        -----END PUBLIC KEY-----
        """
        let token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0.vY4BbTLWcVbA4sS_EnaSV-exTZT3mRpH6JNc5C7XiUDA1PfbTO6LdObMFYPEcKZMydfHy6SJz1eJySq2uYBLAA"
        let key = try ES256PublicKey(pem: pem)
        let keyCollection = await JWTKeyCollection().addES256(key: key)
        for _ in benchmark.scaledIterations {
            _ = try await keyCollection.verify(token, as: Payload.self)
        }
    }

    Benchmark(
        "RS256",
        configuration: .init(
            thresholds: [.peakMemoryResident: customThresholds]
        )
    ) { benchmark in
        let pem = """
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
        let token = "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0.AJCCTYfWKXUPf6dztCbYoVdB4E7FjvmD9WogWtZv20mL6Urt-fFU2DntUIBmoFXGJ5424ubslBt6sk5yBxS_DMnXKfhj2R-J6xDkT0vlldfFzrrDSQEIsbiErfmfVK40Fr9MW4XFKBZdKEI6X35SCmLx9s5RsQCejIo9pdHyx6jGbfXqN_04RWprx6pcqqOn6_Gm4jkofAd1duZ_IUlojUBKX56OgEweR_2glQ8uumb-oklwYl699ZF9DmTKRHHE2RMMT2QVy0RWl1R7HIvUOY0EzxeuKDiiOQC1bFxIH_EZpqBp5FbfW0iemK6Tm5v7_8UzEOmIVrFUIpqxwrI3Sg"
        let key = try Insecure.RSA.PublicKey(pem: pem)
        let keyCollection = await JWTKeyCollection().addRS256(key: key)
        for _ in benchmark.scaledIterations {
            _ = try await keyCollection.verify(token, as: Payload.self)
        }
    }

    Benchmark("EdDSA") { benchmark in
        let eddsaPublicKeyBase64Url = "0ZcEvMCSYqSwR8XIkxOoaYjRQSAO8frTMSCpNbUl4lE"
        let eddsaPrivateKeyBase64Url = "d1H3_dcg0V3XyAuZW2TE5Z3rhY20M-4YAfYu_HUQd8w"
        let keyCollection = try await JWTKeyCollection()
            .addEdDSA(key: EdDSA.PrivateKey(x: eddsaPublicKeyBase64Url, d: eddsaPrivateKeyBase64Url, curve: .ed25519))
        let token = "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0.UzwX3znh-Ne180bcZqjbTk8Dx-BmHR_IL6b8wR2K2AG5f8ny-vThSL0b9IUvR8ybDkUiubpqlKKQXrRtbKQzAA"
        for _ in benchmark.scaledIterations {
            _ = try await keyCollection.verify(token, as: Payload.self)
        }
    }
}

struct Payload: JWTPayload {
    let name: String
    let admin: Bool

    func verify(using signer: JWTAlgorithm) async throws {
        // nothing to verify
    }
}
