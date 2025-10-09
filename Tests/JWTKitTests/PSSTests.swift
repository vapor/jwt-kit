#if canImport(Testing)
import Testing
import JWTKit

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

@Suite("PSS Tests")
struct PSSTests {

    @Test("Test PSS Docs")
    func pssDocs() async throws {
        await #expect(throws: Never.self) {
            try await JWTKeyCollection()
                .add(
                    pss: Insecure.RSA.PublicKey(pem: publicKey),
                    digestAlgorithm: .sha256
                )
        }
    }

    @Test("Test Signing with Private Key")
    func signing() async throws {
        let keyCollection = try await JWTKeyCollection()
            .add(pss: Insecure.RSA.PrivateKey(pem: privateKey), digestAlgorithm: .sha256, kid: "private")

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: true,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let token = try await keyCollection.sign(payload, header: ["kid": "private"])
        let verifiedPayload = try await keyCollection.verify(token, as: TestPayload.self)
        #expect(verifiedPayload == payload)
    }

    @Test("Test Signing with Public Key Should Fail")
    func signingWithPublic() async throws {
        let keyCollection = try await JWTKeyCollection()
            .add(pss: Insecure.RSA.PublicKey(pem: publicKey), digestAlgorithm: .sha256, kid: "public")

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

    @Test("Test JWT Payload Verification")
    func jwtPayloadVerification() async throws {
        struct NotBar: Error {
            let foo: String
        }

        struct Payload: JWTPayload {
            var foo: String
            func verify(using _: some JWTAlgorithm) throws {
                guard foo == "bar" else {
                    throw NotBar(foo: foo)
                }
            }
        }

        let keyCollection = try await JWTKeyCollection()
            .add(pss: Insecure.RSA.PrivateKey(pem: privateKey), digestAlgorithm: .sha256, kid: "private")

        // Case where foo is not "bar"
        await #expect(
            performing: {
                let token = try await keyCollection.sign(
                    Payload(foo: "qux"),
                    header: ["kid": "private"]
                )
                _ = try await keyCollection.verify(token, as: Payload.self)
            },
            throws: { error in
                guard let notBarError = error as? NotBar else {
                    return false
                }
                return notBarError.foo == "qux"
            }
        )

        // Case where foo is "bar"
        let token = try await keyCollection.sign(Payload(foo: "bar"))
        let payload = try await keyCollection.verify(token, as: Payload.self)
        #expect(payload.foo == "bar")
    }

    @Test("Test Export Public Key as PEM")
    func exportPublicKeyAsPEM() async throws {
        let key = try Insecure.RSA.PublicKey(pem: publicKey)
        let key2 = try Insecure.RSA.PublicKey(pem: key.pemRepresentation)
        #expect(key == key2)
    }

    @Test("Test Export Private Key as PEM")
    func exportPrivateKeyAsPEM() async throws {
        let key = try Insecure.RSA.PrivateKey(pem: privateKey)
        let key2 = try Insecure.RSA.PrivateKey(pem: key.pemRepresentation)
        #expect(key == key2)
    }

    @Test("Test Export Public Key When Key is Private")
    func exportPublicKeyWhenKeyIsPrivate() async throws {
        let privateKey = try Insecure.RSA.PrivateKey(pem: privateKey)
        let publicKeyFromPrivate = try Insecure.RSA.PublicKey(
            pem: privateKey.publicKey.pemRepresentation
        )
        let publicKey = try Insecure.RSA.PublicKey(pem: publicKey)
        #expect(publicKeyFromPrivate == publicKey)
    }

    @Test("Test PS256 in JWT")
    func ps256InJWT() async throws {
        let token =
            "eyJhbGciOiJQUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6MjAwMDAwMDAwMH0.dCaprjSiEw1w_cS2JzjWlp1mxdF9MV86VMylKiEZf6gM8NZhNo3hgnI3Gg7G_WL_bSzys9Z0QtNpWZeW1Mooa29qDqZolQLKbzyjiIMDFBslz_Hei-tI5318UdFLKIlMT0VyDThwFjyPCiVEvOkKokWSXXGZCHArGXouTWvaTND9C0gOMwSkE8cHU7e0u-_pDEfdv9MRQiGy1Wj-9T_ZN6a0g8yFMQcOU6voo-WSY-m98oylYOifiOighitlD0xNScDnxBH5Qp7yyU81m-s2-xoYVQJhGduvi8mxbo_bU48WIJfmdAYX3aAUh_xpvgcd55bdeMT55G_qnkDBDSLvbQ"

        let keyCollection = try await JWTKeyCollection()
            .add(pss: Insecure.RSA.PublicKey(pem: publicKey), digestAlgorithm: .sha256, kid: "public")

        let payload = try await keyCollection.verify(token, as: TestPayload.self)
        #expect(payload.sub.value == "1234567890")
        #expect(payload.name == "John Doe")
        #expect(payload.admin == true)
        #expect(payload.exp.value == Date(timeIntervalSince1970: 2_000_000_000))
    }

    @Test("Test PS256 in JWK")
    func ps256InJWK() async throws {
        let publicJWK = """
            {
                "kty": "RSA",
                "kid": "public",
                "use": "sig",
                "alg": "PS256",
                "n": "\(modulus)",
                "e": "\(publicExponent)"
            }
            """

        let privateJWK = """
            {
                "kty": "RSA",
                "kid": "private",
                "use": "sig",
                "alg": "PS256",
                "n": "\(modulus)",
                "e": "\(publicExponent)",
                "d": "\(privateExponent)"
            }
            """

        let keyCollection = try await JWTKeyCollection()
            .add(jwk: .init(json: publicJWK))
            .add(jwk: .init(json: privateJWK))

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

    // openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out private_key.pem
    let privateKey = """
        -----BEGIN PRIVATE KEY-----
        MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQCaCfo4dC9OBEl1
        497MgHOq6OL2Amz7Jcn3xuNZjyPcfzneSVA+2SmNdxx37xrqNf+ej17MpqQSlaiS
        0X9WkD+tFO7VvkiSfPbNcIbMXauoVQioOX5i2yga27Dx9ywyfF7OIjz1ighgvw1T
        dLqzDqd3uT19BSX00TpEZA+3rMKoOaEPuHLSDep7IWZhwa8cm3b3aHSlyjSlt6Gh
        rJv4u852rDeeT4iIfCsbstUK+Ag4IdlN2Fmuv4jlZ+uamcZJjBZ6C3+ql9ykdhuJ
        tTy+qvFstbQm7pYHjJLGt7t5EHkqZBmWXPJOft/8wJf0t7Joj9kbx7wxKjM37Jvm
        Q2lZu5KJAgMBAAECggEAQksa+iLenPfxWaBJKb/6h8qUqwWeO3Qm+NEK1WdqKqJC
        mGz68SFq5awmf2NTNQsqSOYxCWiKYkkwdIdfAzUvgmDo7Opot0q6uO29xcRmdRqr
        kCK2RvtExlJYU7pptgyajKJlk9LlCiYPKSSqmRcscbUyRlTp4fQN3JMnxIfAer8v
        dKGYVvZ3FXWcFS7c/ogDlAkatFmy1J7fJpAitH1BALEC2j3uB9+AZ1ILTcGWrj4i
        VaLuPto8ySlGsGoq2a5uMMZ9l8+AEIvDSdvPOpe6uzFqLDNDsb02YFm44Q/zrfr1
        Tsg3PIRH0dKi2kMVkUabZg0Ius8j0LtS/4DhgDqFBQKBgQDQlVuBRqnt6H5VKkY7
        jqVvackUBeKeY9tAzErHoLc4UKr32A/gPA341YTQTG8Jx2AmII9HfWv8Bk3E9Txm
        YFZRyFNzsup9MVWAJzjmmBelbA+sAnFbpvuHKwEw6Mm3B68g113PNFKZFKtv8Ioi
        5oxLdAj02CA5b7H3rrgcwcGWxwKBgQC9Dl8c8VtPJDv/7+f8RNLERPWyR+oQKywr
        xyp4VKRRVOcMt6M7cB0yL1uMl7dhI4lI6ZUGA5z7Tz/pAHdGvAHJ9zqbhGWgAC0f
        9UcKAUyIx2Ja1QMfxjR7rbhBLswezBXChFTBMo57Cl6BdMV2/5Dy0u+X9hknpXlo
        QoJwyhP8LwKBgQDOSekmAe0uDjJjqFutq3aSqdzkoK1wWPIPM/0BUkHiwGVWmamZ
        68slvoaMPAvVcAn3q1wJKFIT/2gK0z/ZQI4edDGUy+59wrz88c2kwechA668P+48
        5vj8xdt3s8NL8Z2SrW1p8CWAoKCtJQh5W+qE9U2mWdoE9CLfAz2zsyzzIQKBgD27
        q6MvzLkTA+SW2hGuB4S/X9tPUEbnUg0Zg+y29tD4AFpOvKZz/ZSdki9eeyrlB7cf
        TuIf2+rT/fJ/jHM0gQEKEcEmgmi0pgeBeCj0M6GWOa+fTt3ZQtn/5+Kg/VYxHgne
        XC6Z65yRzjpHfxNUcGhaKJJecehYSESbMyzRT6VRAoGBAIcrVYjy0losUQx1jGR7
        XrUn2I12rLjiNmaxub78SJxWRd0TXywSh/CPdX42xs9ku2Rur0Ar+NweEb7YQjZX
        c9YrKwe4kFm7wawf9Sy+9ZvkSqNJ6TNgsw9W+0wRfPg20XuIva0GkNjIZOuPIZuh
        6Bk7+8zqXKzCGABDnrK4h9Ss
        -----END PRIVATE KEY-----
        """

    // openssl rsa -pubout -in private_key.pem -out public_key.pem
    let publicKey = """
        -----BEGIN PUBLIC KEY-----
        MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAmgn6OHQvTgRJdePezIBz
        quji9gJs+yXJ98bjWY8j3H853klQPtkpjXccd+8a6jX/no9ezKakEpWoktF/VpA/
        rRTu1b5Iknz2zXCGzF2rqFUIqDl+YtsoGtuw8fcsMnxeziI89YoIYL8NU3S6sw6n
        d7k9fQUl9NE6RGQPt6zCqDmhD7hy0g3qeyFmYcGvHJt292h0pco0pbehoayb+LvO
        dqw3nk+IiHwrG7LVCvgIOCHZTdhZrr+I5WfrmpnGSYwWegt/qpfcpHYbibU8vqrx
        bLW0Ju6WB4ySxre7eRB5KmQZllzyTn7f/MCX9LeyaI/ZG8e8MSozN+yb5kNpWbuS
        iQIDAQAB
        -----END PUBLIC KEY-----
        """

    let modulus = """
        gWu7yhI35FScdKARYboJoAm-T7yJfJ9JTvAok_RKOJYcL8oLIRSeLqQX83PPZiWdKTdXaiGWntpDu6vW7VAb-HWPF6tNYSLKDSmR3sEu2488ibWijZtNTCKOSb_1iAKAI5BJ80LTqyQtqaKzT0XUBtMsde8vX1nKI05UxujfTX3kqUtkZgLv1Yk1ZDpUoLOWUTtCm68zpjtBrPiN8bU2jqCGFyMyyXys31xFRzz4MyJ5tREHkQCzx0g7AvW0ge_sBTPQ2U6NSkcZvQyDbfDv27cMUHij1Sjx16SY9a2naTuOgamjtUzyClPLVpchX-McNyS0tjdxWY_yRL9MYuw4AQ
        """

    let publicExponent = "AQAB"

    let privateExponent = """
        L4z0tz7QWE0aGuOA32YqCSnrSYKdBTPFDILCdfHonzfP7WMPibz4jWxu_FzNk9s4Dh-uN2lV3NGW10pAsnqffD89LtYanRjaIdHnLW_PFo5fEL2yltK7qMB9hO1JegppKCfoc79W4-dr-4qy1Op0B3npOP-DaUYlNamfDmIbQW32UKeJzdGIn-_ryrBT7hQW6_uHLS2VFPPk0rNkPPKZYoNaqGnJ0eaFFF-dFwiThXIpPz--dxTAL8xYf275rjG8C9lh6awOfJSIdXMVuQITWf62E0mSQPR2-219bShMKriDYcYLbT3BJEgOkRBBHGuHo9R5TN298anxZqV1u5jtUQ
        """
}
#endif  // canImport(Testing)
