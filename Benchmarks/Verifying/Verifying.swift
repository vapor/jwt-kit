import Benchmark
import Foundation
@_spi(PostQuantum) import JWTKit
import Utilities

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

    Benchmark("ES256") { benchmark in
        let pem = """
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
            q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
            -----END PUBLIC KEY-----
            """
        let token =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0.vY4BbTLWcVbA4sS_EnaSV-exTZT3mRpH6JNc5C7XiUDA1PfbTO6LdObMFYPEcKZMydfHy6SJz1eJySq2uYBLAA"
        let key = try ES256PublicKey(pem: pem)
        let keyCollection = await JWTKeyCollection().add(ecdsa: key)
        for _ in benchmark.scaledIterations {
            _ = try await keyCollection.verify(token, as: Payload.self)
        }
    }

    Benchmark("RS256") { benchmark in
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
        let token =
            "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0.AJCCTYfWKXUPf6dztCbYoVdB4E7FjvmD9WogWtZv20mL6Urt-fFU2DntUIBmoFXGJ5424ubslBt6sk5yBxS_DMnXKfhj2R-J6xDkT0vlldfFzrrDSQEIsbiErfmfVK40Fr9MW4XFKBZdKEI6X35SCmLx9s5RsQCejIo9pdHyx6jGbfXqN_04RWprx6pcqqOn6_Gm4jkofAd1duZ_IUlojUBKX56OgEweR_2glQ8uumb-oklwYl699ZF9DmTKRHHE2RMMT2QVy0RWl1R7HIvUOY0EzxeuKDiiOQC1bFxIH_EZpqBp5FbfW0iemK6Tm5v7_8UzEOmIVrFUIpqxwrI3Sg"
        let key = try Insecure.RSA.PublicKey(pem: pem)
        let keyCollection = await JWTKeyCollection().add(rsa: key, digestAlgorithm: .sha256)
        for _ in benchmark.scaledIterations {
            _ = try await keyCollection.verify(token, as: Payload.self)
        }
    }

    Benchmark("EdDSA") { benchmark in
        let eddsaPublicKeyBase64Url = "0ZcEvMCSYqSwR8XIkxOoaYjRQSAO8frTMSCpNbUl4lE"
        let eddsaPrivateKeyBase64Url = "d1H3_dcg0V3XyAuZW2TE5Z3rhY20M-4YAfYu_HUQd8w"
        let keyCollection = try await JWTKeyCollection()
            .add(eddsa: EdDSA.PrivateKey(d: eddsaPrivateKeyBase64Url, curve: .ed25519))
        let token =
            "eyJ0eXAiOiJKV1QiLCJhbGciOiJFZERTQSJ9.eyJuYW1lIjoiSm9obiBEb2UiLCJhZG1pbiI6dHJ1ZX0.UzwX3znh-Ne180bcZqjbTk8Dx-BmHR_IL6b8wR2K2AG5f8ny-vThSL0b9IUvR8ybDkUiubpqlKKQXrRtbKQzAA"
        for _ in benchmark.scaledIterations {
            _ = try await keyCollection.verify(token, as: Payload.self)
        }
    }

    if #available(iOS 26, macOS 26, tvOS 26, watchOS 26, *) {
        Benchmark("MLDSA65") { benchmark in
            let mldsa65PrivateKeySeed = Data(fromHexEncodedString: "70cefb9aed5b68e018b079da8284b9d5cad5499ed9c265ff73588005d85c225c")!
            let keyCollection = try await JWTKeyCollection()
                .add(mldsa: MLDSA65PrivateKey(seedRepresentation: mldsa65PrivateKeySeed))
            let token =
                "eyJhbGciOiJNTC1EU0EtNjUiLCJ0eXAiOiJKV1QifQ.eyJuYW1lIjoidGVzdCIsImFkbWluIjp0cnVlfQ.SVUaEaML_57ttl97jzlGk9qLuU7TRYSrse2t5flwHavixPZU1SnpThnzFxaNHcQ2V4Q6X_RRrc4AJZebzfe6MMPz6cFkvX4cPdHVDAttSuVebe27al6l2_XJTnZmF9KNMsgTLFC1TNVxXiBSStN-zNGMtdiKZsuLc_Zl96__de0YVll5jyeqAxbdSxORK-49mP121PVzbXMH7sUXrXoaCsl7zqjzMY1qNPOyYa40wvFVHZn35beaN4fpCe0Qvx-UR1YCVOWgnTacaOShVLzW26WRDO1uVq_wo4bPsOHRNJ6Zuew1f9ANaahm_PlpzQYgQ6Q4R3i7cneL9zxl8eDsdp6pGSBoEdhGq34L8pL8yVzX-OLqaDgoDeBRdg95EzB24KoXUEhE-pl4_s8QbvGr_cmYbqz6NVLsOD5_nl-1wPi33O0xr1Ds-0FiDbRyikfrfAcs4DYUUtfUnXP9Os3MaxZVxGDLFNsntDKMi1E-tTF50i64uR2O9nyJpShfRPgxNdsxYpp8LhXdv8jOEvfSWC217D6qKpU1re_9rnohZWrPoQyV2CuCYgDVz4nCrI_vYDT1iCkVmiq6HpASiNtMyS7ZG5Y9QHaIXWorzD1yHOLXzjuwUDha3FpXE9To4CgZu70lv4MkIM5X8h3syTUO1abS1VtdJvO2K0-7Y6qZbbuCYmD777RBbW7WMiyoa2Nh-ZHPsM4PWZqbLjKyMZ7xWK8w0iFK9vxw_RMNPt5AV6I4IBtwn-D336wkm_s7GJJQYGKDkaNKalX1JraKuCGvevxKroT60kKQMNTRtRTW7jeJ096r930UjHjlaFwe4OCE_R09-deZU7LIi1OwA6DvKwKLUaZerjLIZhS37x3tFtU6dZbi4V7ytIk-bASVzaPjiZPaWM8_04yzZ7WyhMmcoVw-SkKyQLtctlT2UkxSB_ydcUYJWW-rPlxu-XujquAicVw3qYji6qd-e2-ntuwUQWCLyKsWKhAC2SK9K8WRnXVlciTPI7-Rr7ZnAYkYqTrhwhgBBDz1g_ZjiVZjmC-wdQ-yy7LEP9uSEJ1oRvz6U-G2LzHtCh_ZgkvkCWB-7KfnWWvE6H33N-tBABNFceHWncinDMj3jtBGEsCDnB4EQkgvgDv9LhYo6cl0tIvBANRD5xudTABpNW51_7iMRuWxQUQdB_WMabkpZcwqNklI8u4L0cbmJ9lGFeyu1FvLxNLBFpED8Nr5Mg7XYy4nVu7RMX3rpk6naBQRSPwY536m6TJnO9Vh7UZBhbevGy5d7jfvi4KN-GDvE4e_7sMMjE-gw2Sp8FGWI_ZjGShbOZXWcM0HQDYpszD7JPWpv2d_68f8e8NP2cIMioK0oZwpQePRa6ddCM1UpWlVDb5aK2YEQKTJGb0YhnZkg-PUGy068iNB7SxajEqVwy-j9cCl1d35VOmcSs7TGQg-UlxwheIQHS25C_tK6KDTUoU4CjvMgEt8I0fvcpsjknXU7VF1TYOiR4RrEXf2XsN2eDxmlW1a9C-61hz1aOb5e1w8NNX6d8nmbF2xqTLgKf9Xg7XnU4nvt4Na8-ltGefWL5B-L7HNRJ9QZzcavsajuChOl9FlbAFfhkKFZpYDWMb-MzQSmlTwVEB8S6sly5aDqN22o8263WHlNPeq6dJuvnHcufkv6PX2yHHPLhsTCx6aI9hYF8E-9OGsdowh-y-oPhH9hyFVjgrAhryLuUAczo9XsLaClAC6iQ5_58d35lDopu_r7TZ3sdCXIpzgtdKFPu7beoZKBWULTe3y5JVqLd3pvTY068skcP7TCIxHOg4hPCyPrJH9swJ0xbNMaiL8vDf-mSe0led_OuYbhNKDFVJtFNZEGbkBef8cob13JxVuU4Lm0UTemvV-yPpgH9SJ3RmYlp_7-aVBQdZ4UOe0uHTMiopsOdr7hp_GqzPfYp2d6yYtJvczIQIGnGCAAk8QcE3HDmxMYvJv1rQmupeYL2X7CzeoPoaU0r416nIfo7sP8-8q06DqlDvT_11eBnyFjIW2FzUobVec642zluLoZXkfQdNrCbx44pvwojxk4D1PmUlUKD9BIVmeDYIy0evUIymYetlBmnTeXVgwkcDBq4LWCHOZNsFjrF5wjmqNZu-UfH3yiVOStq3MLl1W4D2lV4Fn8G-8gPgnx2qoFNQYIApK_Hpvr6V_nFP33qB2SW91pptF0F6a5eEMpgB3nM8xwvDw3oy4lWA-X70WOQnriMu0hzVxJvhPim4LY0r5RcdXgYzAJq0uw1FhSJKOxCuZplAOiIZ1gDLdW0BDcR3xmsr_zqijgL_HL_VGJfsach9wAG28p7oG04U9__SIhMYC7g_2mvCG8_BiRu3lTY13hXi8_4dNi2wDG6iyL2bDADu2VuyEYhXnvuEU7qOeTB56nf5r44wvHrus6SqXpxHIDMV1x5iEOmUaVwaxoq4wayCSyW5GLMVUOAlzgpjlf5Q6AymH9F6qoVuV5QnPfrc2Hd7hitzmuq-AqnrhhuFh1wzjtyauCQWA5bWUTFJ0Ejxt8SSHk_wDXBjjzceiQvPujVxpO9xt_82Xy1w74pvc4odu4hZjhQ_mfllv-N07R00kn3B0RqRSiLS34pJV9PagX59XKBl9IccYnLTxNfIac00-tK5bBN5USCJ8SpkrMF3eNNE2Dy88hG4jxHfszyN4XlrvgolM60jU8b8wXGgZNYjBRYbZ34LVkST-AfGJKDU9AK1UQxkJG2QjwiyfRidQGgXrzAT5BVRvFqXXl1YMBLfT_Bnq95gB_hzfMpCzbINWgK6vz66oZ0DI_6u9otjJJt4gVItt0fheV-MpDwigX9U4g6AGxI8Wk21aC_Y8XDqTRERsrxROxUKGRKF34-r7H_wgbuu9dtVnfOl8CReNi1u_UaL50ekGDsjtKS3gu5jwxQTEd2fU0U__gSN7wjnGViexBio_aPFQdN4RP3Pkwcrq7pJvBm2u32W2oJ2sff_uY887LkHTmySXHZz4EzVOynxRN2ivi4TCuJELr5xS60PGSUo0Tq4-9wdygIBJIkwpLHSVyQRBlAoan5vO6XKGLwUGHhsCdBC3cqNKsoKRODKXKPzBQbZt94vnkI6GImrpUchICQiLEsLKyWcqSHpcuZ4zYkfxUJGCtouyBsttWokavO6zWctvsE53OzwmlpHf6Km8PpUQIkzKcRgeHVtwoSchXhRep5WpgcyywJs4PWmTUUXT-uyBaqSNvxkNqagmU3z-j9ZvcF4KYSLtgCNo4nl1sih6Y-u7B5s2rOvlF8BqbCLzD2laILmIzJpyW04tTmuro_dVAT7Q-pX228pOrkidkpT9z-heASWOcTysx50Pcd_DyNxsz3qDl0UDXz1RQorVsqklE1DVjZikPxlkfiAin911ZBFf_vVN467M0S_tv927t8mMbPw3Cx03J6UcuRc8U3A1n-3lLuHpQDawl6IFkGRGy-TIWf8o4XHdLnEZy0n0J2rAl5ZdydhzarV2x9BqD7BnnA26tx6FZ5vp1l-IDSuviLoUqS6oO9Ta0splnriiSEKNghPv_TLeMBZJrqhSWVl0W3RXOWAaQ0vu3-IaoXQtteEHSTkdBAuFMxC-KVpeAipDffgvseBIvde0ljeSksGWZ-3t-bvj3hqNoffYU5tihkurKr0JSUjIUUprUR9h77qMwfxvWFEo7zsptU8LPc6UL0EBW-JAHvZVo1WmN5Y5UnBmWJdEJpHzTXqniHVWtiaEkzqUq9DJihfXV8MpBhUXfQl-b6DoM35SPuOGknP8MuoOTr4n-lxqn4JNU9C9zXDpkF6ZU7aeMmKLSFVDSxgneeqr3cNGO4Q5jmoSfSSdi1sXV4egciGqdRzDho9czMNDqXhbzlOKmxTpiGhGQLtgDDeEBSUIDsKmJE9fjVPFfNK1PjsAU8DgA8ixI714Lv0aQ9r-tK-P-_URh4avkoq0b_FNIKR-qit13-id35pnQx5bFCnkxRRjasZ8ttY5pIF50HZRI4JqSnuvmbsckpncoOEATdhKxzl2LOjcaWJZERGpGs3r85haKQ0x6mjE-fiizeuM5GwxYJpYIBryQUJ4w2O-FVUiZWUHk4HouGVHTKhQ7q_dWArhYOle5KryanH9fM-A_Pak7vAUvxI6MIimZP2afRNpLyb-fkgikdZwwYSty32stJhC3vF1Zu1zSakIpECdYrVH_GN-0K0GDh7jR7wU0orB9hLgs0wrfVU1o7JdXT6SGsaR29-NxOnv51gnf8esqghWVhWTXFxUdXF8GbrI963_9Gj9O0RbdEnIOsaLMbVhJw7o0Nu0YVpNfwBMmPd76kXc-i6A6FKhq88i3sUXGGCHur3W5gNNXGZv2v3-IGN5jZ-u0OLuHj9Ccn6BBBEZPD1QbISZvcrc4XmIosTKAAAAAAAACBAZHywx"
            for _ in benchmark.scaledIterations {
                _ = try await keyCollection.verify(token, as: Payload.self)
            }
        }
    }
}
