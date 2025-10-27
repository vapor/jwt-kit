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
        Benchmark("MLDSA") { benchmark in
            let mldsa65PrivateKeySeed = Data(fromHexEncodedString: "70cefb9aed5b68e018b079da8284b9d5cad5499ed9c265ff73588005d85c225c")!
            let keyCollection = try await JWTKeyCollection()
                .add(mldsa: MLDSA65PrivateKey(seedRepresentation: mldsa65PrivateKeySeed))
            let token =
                "eyJhbGciOiJNTC1EU0EtNjUiLCJ0eXAiOiJKV1QifQ.eyJiYXIiOjQyfQ.hsk2p8N1ScHi_Gj97WZRqm1c01MsIic8imHnvr3DjNEIfGqTScqiLqyjfd-tm1OsYQko1VI9y-g9RjA8YZPuVxXTHrQ4qOz_xXSL9nAA7_ddoknU6YOrIBQNMtoqEajvZFzfGcWVoQEniocIfXpLbR3e4fyoQjqRoQPkXNJpoE3Sw6tetMNdhL7_c_oP1ClM1sauUZTTYm6DhTvDoNV3swxh9t_duMXTLdxETN4pAb_G4xfrXqVyjkRFA5cJ9HK5Y5MXGUPRKD2VK0osuhbdFcPT3Bec4JGnVKxOYvd39p5w_WKGiTmwsRv9yE4fkXyvyDhCBHt1xUKc_6yVQl8Db60jcy5T5nLuc2TAZwTRllzSVzoFyTzlQ7edh2A3NJfiqWCF_q4y-QF3Usoiv8H4aFT22lZwIDCFpxcWQIwjt1M8WMJbJYROV6cK3c1nl0kgRfxcpq6PskAZiQ6L4wH83lwrNWGMWTGwLSwYcxtjgT3azucbrzSXBhv9JZ4nE2q2ek3sWBCdIj81qL4iVLDpOfo1jcerB1i35SWXTTTP1ROR3AfJLJR7QCLi4uEaYK1mUG8xH0CUuHL48C-ymXYMhFaz3RUPXAXMD_el3lkZDTHDQhEPf7LbXJDrId3v0-FSE187SZaW_8bAqPVMupZXU_TKvGD4juan6xQFv_0pS2sqXVLjvmMmdZPq1tj2aZuGCvReGMih0K_l8UYhAL_sm2QDt34Cjsw1ZlGkc6lJJU4ow38xl7_f3efFvuZFRT8eyoRP_s8Ld8JYOi360BL-tc5VMj510tpa5eBN3GpgnqpmhCHHPUnsiHuNdJWLmbuS4zMTlJTQ0eCkun6Kc1v2rrO1TVRIqs1aUDCTu8jsGQsZe00rdIvSU3HAJ28n6_P13sCI5JpT3pbMRdTjstzkXhGgA_D8bmjFAsV5UwugVYjTJ1u5S4hw1CtIMmV9a7uaq0MY7G58suzDzZCg14rBvj7DEWTljWZNV4OMs5m9dc42lcgZ5CC6N5ft_rNqbclkD1XJ-bbh5-halnOocQQl9J1uA7iVBoLd_tx4WOvl9RdhdEc-wVooyZ_BmXlvh1l-L8zSfmZm3r8EQcHPUhtayEAXVA7eVoNT-wAfXpV131pvjyVcxYyS2xbuHmCvL1VP5T8Ujva_aNINgZxU3w3hEzIvwZmKbkkyLpFSGPb9JmKryDDINJhu2TYJvQhhdgOkYe3IP8bEJUUiEoPI23SXj81OSgBo7GHFGooPk6FrBwnZJFOW31-SbhESYhnG0jfNeZhJhTGZe1Q6U7Ze4L_DJkiwlmebPKjUBIzSEs4HmR9-lpT05OUjuuFxOeg31MmHkuwGBbOcMxwaHZsSw40zbAYM7ktRYzPBA6MXeOojm-T3O7uCp8QCBArKlUN-rIeUSAlj76Fu6axdLzhZfT5YWzapODb0GIZAJAe4fwB_WFQuBjuR9J0JOSHt3dePL6XJAsKpBfszOY4vSjNHXdE3O3P-boAKOaOZvI4He8WKhyMENG9EaWQLlrWLnaOOIbygwDHDK6mdndvgaklyopa-jMne_ehdjTkNtsMW2uudNKisrAoUka-5kJrQZ3Rpe34DshXPj1ghRAjVk2igdozEJ1s05fgo4QzqaQPjuCbOHRLa1kOCB_G9A5ltJo88CbDRUVm-8_mR6tGiVbal5M8jMwJtYDNZV-Nsa7MWg2dVg3A63e4qpsuDgajpDxplZAFsmulGWOyeRf3tRt0GXDVMGEGdjW9iHuY5XqHN4Dz4YFPIR6NZOgfCGLrLSDyad4U6oxOmmliptmtkq6_12j_H2SV7YQT2e7rhBxTRlwsLWck6_tX3QbVfCBBtUzaxI4-FsXLKIFyFOAtE2Ng1OvYtAm5ZPE2GEwdWS35tKSaAztnKskiJ8mS9vslzo72ggoysFQeGRKC-hjlJ-EomboSrmMKjebRDQqeVq2qzFcYCe4HgPrvhEubTb0uXRLurFG8WmChBTntQc1NHI-dCsnsbDzJJoqHyuBsXQbMoY4E-Mr5QLwMKAQl0aDQ2jxdn2Y23c5oPXfKGeQy8Y6i3QIneLeGzpXbRcFZrs2BOcqAkREqs4n1qIYhwElbMgetVPVg_lIVUmY8XaH9-SCSKwncALVJm03WGCGwfEpnackyIO_i545shq9vcW_D_druZVszLbTYd7oERAOVGGL88K7u00fLpyy7rsviz_1W0HFPhlV9iTKk8uldMg4C1NMTQH2Y9IJ3D__PVfPF9hx-xMPyPK7wzC4M-nJdZop4bQYG36x4zKobYMQbNdOSSmK3poclPKzCTMH0RaMp6zynqPBVP2l4ow4gGNroH6eKVs-lVFrg3_pjnGR1fLKIvpCfkJs-TLSfw9uZrvdReMrTOvriF1wnN7uHnpCJ_Oj_NEZVGy-mH49owiNaCNu15Nt0uhqhwGQ9KlI_Einm771roQkX_XSd0if8PRvSwD427Lx8s9LMJ8JuAgu68FuAg_SiCNCnFVd7P4hTW3fI8OUNGEg40DcDxWdIRYYJ7OIeSh7Wgfa7Bk1VJ3jZs43KalQqApdTHubYdRfUjSnBG43egRO4YtZyKclQrlkQp6Lrq74tM8xPAnwr_Q5gwzoywgcnM-r3eoiZZ0qwJ40vMelEXhaoVWCWrBrjCj8Jq4VdOLMwzZBZVTHr72T3stNCECc5LWVjXwlKtVsAOP29T7cu90dJAFVwqIW-8gejMtVLLXTRiZv8k0plkPLJUB6-YyHGnIL_e-xBapj92G566Tuo-X4YDqzfuHVb7fgZit_QFcxl-fgfOlk0d1zeQc8g4oRzyw9M8NDWMBIPOlLF_CjxfrLhnmLGM52KP6j0jZEizTREsLOMS5vrTLQXq7EzBaB-7BUNGR5TjwojdUJexzKRNIGRXnmthUF587uxhIJ2EanK5ruhZX4iBuesEpMVK4B6G2WdMisSYm3M0fxOGmiIGiPzlU_k39utAvL1tqC9wD1w-l1SyZQHCmgRuZ6HiwprI4wqe5tGwqKn5fJN-Z6U1zyvq_jXfiwWnUR2GnagMMCYUlZQqlIxEBFVlJBC3-mbiPXvf-m2fy2BagmJcE3YCUU-uM_PkiO6ecqX6buraxjxexDbTdbH9VQo8u8MMSEX2IP9zZvhadTxu1k5lKvo3ZWu0jipz6Jg9HdLoJZiVN0koNoJmZXIBhXwNsVy4cpD1F8AQuI2IQDH_P8cKOrhbW_DzPcNk3Ec7bggNen6LxLC6oRHUz-mbqS5WvxBgUBXVayCiMByEX6wzwra7ZTA-9vRJhuC4phi5rM96cQFNfkTNoKj0hhvgYYdUV4XQtEDt3OC6H5Wrl3hDDqb2ZSsxZZpCly0C-VVpINBa78z9Kfegf-Mmj1akOeEUuCwJvlD55tQp2_n5BaSoIn_4qwKAiOE8JmZuEpfmk7qcjI-grh3q0bUBdikv7W0b6ny2uGa7u1dxXyGMH2C_FnLYEQZiPMO0DpD2nyOOm9Fk7vqaAmhTItB99LzqCN7PrwMz1xwidm-XtDWSc0gCcc0-c_1hYuXXHuK0qQ2mgtmY6O79MMmmR3OKEFq-FpwkmD2DFGzKqVvjTm-TRrptBcyyNuDXrRgnDfHHJoDGz-gpAiebTNTtWw3ewzWSyS1L06WihiXtHei6escdb8Rm9O_7178QkLwo6S9c1b0osuEGzOh-_4125KU2Sa27v7RfpDmFR8iNd-d1kA5rlLh8w2-VO_S6AIZ8JgFJmOQI1PjayqWYA-LtWW5Un7IOwIfK4jvAGlesGQ5dFPb_SUTtz3iW8YthqaDPW8_ybAY6Qjt6EnHdM_HDCbQn2OLF5zYKhWBo_bLPW2UiIklkVEv-dCCBZUw_QYspVESVMPlK6xG9gC_pT_MFQ0ncmNdcLXqaMsE4NjaMWMusvpgYnF2PE7uy3TdgsNpFLGGEy9mfAyFsp4YYM_WJrVyVCwTyoNex-ZcxDJ0egzy5CKwEDbqL3NzwanL3Z_1yX-4hyZWwRC-6a0WHBucNqBSSGQExwYadMHcbdcmeJRdkl6sdxnvFsArInXx1qDV-2cBkFTX5551zIHlqu-ZPBA8NmXUNzhe-R_X2mRCJh5-sEA8f8KEdfguPIDgTDQTQiQKyBo-g45cTezt239PIV6ZINDE8suB7veLIJ5Ye3XcUTqyKDgqNU6ri6BbtbhOcs2Jic2bVaLB0MkBvLCv6dprFNinKRKWZ1lUBPn6-fHYXldzJ-qCcfCpdGlTvuzB-WXuw6lgjO8i69tfkOjHMpb4r5mjkCipMreyXSbJMxSJR97MJOF3jfgndxBv4ogwPzXpjR5mOru4r0Ke--RtU5vkSGpLo7f1EbYWLnalQp7fXNEd2S09iofU9R32gr83XAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAABgwQExgf"
            for _ in benchmark.scaledIterations {
                _ = try await keyCollection.verify(token, as: Payload.self)
            }
        }
    }
}
