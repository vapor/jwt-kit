#if canImport(Testing)
import Testing
import JWTKit
import X509

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

@Suite("JWTKit Tests")
struct JWTKitTests {
    @Test("Test Getting Started")
    func gettingStarted() async throws {
        // JWT payload structure.
        struct TestPayload: JWTPayload, Equatable {
            // Maps the longer Swift property names to the
            // shortened keys used in the JWT payload.
            enum CodingKeys: String, CodingKey {
                case subject = "sub"
                case expiration = "exp"
                case admin
            }

            // The "sub" (subject) claim identifies the principal that is the
            // subject of the JWT.
            var subject: SubjectClaim

            // The "exp" (expiration time) claim identifies the expiration time on
            // or after which the JWT MUST NOT be accepted for processing.
            var expiration: ExpirationClaim

            // Custom data.
            // If true, the user is an admin.
            var admin: Bool

            // Run any necessary verification logic here.
            //
            // Since we have an ExpirationClaim, we will
            // call its verify method.
            func verify(using _: some JWTAlgorithm) throws {
                try self.expiration.verifyNotExpired()
            }
        }

        let keyCollection = await JWTKeyCollection()
            .add(hmac: "secret", digestAlgorithm: .sha256)

        do {
            let jwt =
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YXBvciIsImV4cCI6NjQwOTIyMTEyMDAsImFkbWluIjp0cnVlfQ.lS5lpwfRNSZDvpGQk6x5JI1g40gkYCOWqbc3J_ghowo"
            let payload = try await keyCollection.verify(jwt, as: TestPayload.self)
            #expect(payload.admin == true)
        }

        do {
            let payload = TestPayload(
                subject: "vapor",
                expiration: .init(value: .distantFuture),
                admin: true
            )
            await #expect(throws: Never.self) {
                try await keyCollection.sign(payload)
            }
        }
    }

    @Test("Test Parsing")
    func parse() async throws {
        let data =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6OTk5OTk5OTk5OTk5fQ.Ks7KcdjrlUTYaSNeAO5SzBla_sFCHkUh4vvJYn6q29U"

        let test = try await JWTKeyCollection().add(hmac: "secret", digestAlgorithm: .sha256)
            .verify(data, as: TestPayload.self)

        #expect(test.name == "John Doe")
        #expect(test.sub.value == "1234567890")
        #expect(test.admin == true)
    }

    // https://github.com/vapor/jwt-kit/issues/213
    @Test("Parse corrupt tokens")
    func parseCorruptToken() throws {
        let parser = DefaultJWTParser()

        // This token was created on jwt.io and is non-UTF-8 but still valid
        let corruptParsableToken =
            "eyJhbGciOiJIUzI1NiIsInR577-9IjoiSldUIn0.eyJleHAiOjE3MzExMDkyNzkuNDIwMDM3LCJzdWIiOiJoZWxsbyIsIm5hbWUiOiJCb2IiLCJhZG1pbiI6dHJ1ZX0.vvz-_LD_uz1K_BrxzbOWfzpOiS4hRvDztSbGiGlVujs"
        _ = try parser.parse([UInt8](corruptParsableToken.utf8), as: TestPayload.self)

        // This token was created by us but has been tampered with, so it's non-UTF-8 and invalid
        let corruptCrashyToken =
            "eyJhbGciOiJIUzI1NiIsInR5xCI6IkpXVCJ9.eyJleHAiOjE3MzExMDkyNzkuNDIwMDM3LCJmbGFnIjp0cnVlLCJzdWIiOiJoZWxsbyJ9.iFOMv8ms0ONccGisQlzEYVe90goc3TwVD_QyztGwdCE"
        #expect(throws: JWTError.malformedToken(reason: "Header and payload must be UTF-8 encoded")) {
            _ = try parser.parse([UInt8](corruptCrashyToken.utf8), as: TestPayload.self)
        }
    }

    @Test("Test Expiration")
    func expired() async throws {
        let data =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6MX0.-x_DAYIg4R4R9oZssqgWyJP_oWO1ESj8DgKrGCk7i5o"

        do {
            _ = try await JWTKeyCollection().add(hmac: "secret", digestAlgorithm: .sha256)
                .verify(data, as: TestPayload.self)
        } catch let error as JWTError {
            #expect(error.errorType == .claimVerificationFailure)
            #expect(error.failedClaim is ExpirationClaim)
            #expect(
                (error.failedClaim as? ExpirationClaim)?.value == Date(timeIntervalSince1970: 1)
            )
        }
    }

    @Test("Test Expiration Decoding")
    func expirationDecoding() async throws {
        let data =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIwMDAwMDAwMDB9.JgCO_GqUQnbS0z2hCxJLE9Tpt5SMoZObHBxzGBWuTYQ"

        let test = try await JWTKeyCollection().add(hmac: "secret", digestAlgorithm: .sha256)
            .verify(data, as: ExpirationPayload.self)
        #expect(test.exp.value == Date(timeIntervalSince1970: 2_000_000_000))
    }

    @Test("Test Signing")
    func sign() async throws {
        let data =
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZvbyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6OTk5OTk5OTk5OTk5OTl9.Gf7leJ8i30LmMI7GBTpWDMXV60y1wkTOCOBudP9v9ms"
        let keyCollection = await JWTKeyCollection()
            .add(
                hmac: "bar",
                digestAlgorithm: .sha256,
                kid: "foo"
            )
        let payload = try await keyCollection.verify(data, as: TestPayload.self)
        #expect(payload.name == "John Doe")
    }

    @Test("Test Unsecured None Signing")
    func signUnsecuredNone() async throws {
        let data =
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjIwMDAwMDAwMDAsImFkbWluIjpmYWxzZSwibmFtZSI6IkZvbyIsInN1YiI6InZhcG9yIn0."
        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let keyCollection = await JWTKeyCollection().addUnsecuredNone()
        let token = try await keyCollection.sign(payload)
        #expect(try await keyCollection.verify(token.bytes, as: TestPayload.self) == payload)
        #expect(try await keyCollection.verify(data.bytes, as: TestPayload.self) == payload)
        #expect(token.hasSuffix("."))
    }

    @Test("Test JWT.io Example")
    func jwtioExample() async throws {
        let token =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA"
        let corruptedToken =
            "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HwP_3cYHBw7AhHale5wky6-sVA"

        let publicKey = """
            -----BEGIN PUBLIC KEY-----
            MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEEVs/o5+uQbTjL3chynL4wXgUg2R9
            q9UU8I5mEovUf86QZ7kOBIjJwqnzD1omageEHWwHdBO6B+dFabmdT9POxg==
            -----END PUBLIC KEY-----
            """

        // {
        //   "sub": "1234567890",
        //   "name": "John Doe",
        //   "admin": true,
        //   "iat": 1516239022
        // }
        struct JWTioPayload: JWTPayload {
            var sub: SubjectClaim
            var name: String
            var admin: Bool
            var iat: IssuedAtClaim

            func verify(using _: some JWTAlgorithm) throws {
                // no verifiable claims
            }
        }

        // create public key signer (verifier)
        let keyCollection = try await JWTKeyCollection()
            .add(ecdsa: ES256PublicKey(pem: publicKey.bytes))

        // decode jwt and test payload contents
        let jwt = try await keyCollection.verify(token, as: JWTioPayload.self)
        #expect(jwt.sub == "1234567890")
        #expect(jwt.name == "John Doe")
        #expect(jwt.admin == true)
        #expect(jwt.iat.value == .init(timeIntervalSince1970: 1_516_239_022))

        // test corrupted token
        // this should fail
        do {
            _ = try await keyCollection.verify(corruptedToken, as: JWTioPayload.self)
        } catch let error as JWTError {
            #expect(error.errorType == .signatureVerificationFailed)
        }
    }

    @Test("Test JWK Signer")
    func jwkSigner() async throws {
        let privateKey = """
            {
                "alg" : "RS256",
                "kty" : "RSA",
                "kid" : "cc34c0a0-bd5a-4a3c-a50d-a2a7db7643df",
                "use" : "sig",
                "n"   : "pjdss8ZaDfEH6K6U7GeW2nxDqR4IP049fk1fK0lndimbMMVBdPv_hSpm8T8EtBDxrUdi1OHZfMhUixGaut-3nQ4GG9nM249oxhCtxqqNvEXrmQRGqczyLxuh-fKn9Fg--hS9UpazHpfVAFnB5aCfXoNhPuI8oByyFKMKaOVgHNqP5NBEqabiLftZD3W_lsFCPGuzr4Vp0YS7zS2hDYScC2oOMu4rGU1LcMZf39p3153Cq7bS2Xh6Y-vw5pwzFYZdjQxDn8x8BG3fJ6j8TGLXQsbKH1218_HcUJRvMwdpbUQG5nvA2GXVqLqdwp054Lzk9_B_f1lVrmOKuHjTNHq48w",
                "e"   : "AQAB",
                "d"   : "ksDmucdMJXkFGZxiomNHnroOZxe8AmDLDGO1vhs-POa5PZM7mtUPonxwjVmthmpbZzla-kg55OFfO7YcXhg-Hm2OWTKwm73_rLh3JavaHjvBqsVKuorX3V3RYkSro6HyYIzFJ1Ek7sLxbjDRcDOj4ievSX0oN9l-JZhaDYlPlci5uJsoqro_YrE0PRRWVhtGynd-_aWgQv1YzkfZuMD-hJtDi1Im2humOWxA4eZrFs9eG-whXcOvaSwO4sSGbS99ecQZHM2TcdXeAs1PvjVgQ_dKnZlGN3lTWoWfQP55Z7Tgt8Nf1q4ZAKd-NlMe-7iqCFfsnFwXjSiaOa2CRGZn-Q",
                "p"   : "4A5nU4ahEww7B65yuzmGeCUUi8ikWzv1C81pSyUKvKzu8CX41hp9J6oRaLGesKImYiuVQK47FhZ--wwfpRwHvSxtNU9qXb8ewo-BvadyO1eVrIk4tNV543QlSe7pQAoJGkxCia5rfznAE3InKF4JvIlchyqs0RQ8wx7lULqwnn0",
                "q"   : "ven83GM6SfrmO-TBHbjTk6JhP_3CMsIvmSdo4KrbQNvp4vHO3w1_0zJ3URkmkYGhz2tgPlfd7v1l2I6QkIh4Bumdj6FyFZEBpxjE4MpfdNVcNINvVj87cLyTRmIcaGxmfylY7QErP8GFA-k4UoH_eQmGKGK44TRzYj5hZYGWIC8",
                "dp"  : "lmmU_AG5SGxBhJqb8wxfNXDPJjf__i92BgJT2Vp4pskBbr5PGoyV0HbfUQVMnw977RONEurkR6O6gxZUeCclGt4kQlGZ-m0_XSWx13v9t9DIbheAtgVJ2mQyVDvK4m7aRYlEceFh0PsX8vYDS5o1txgPwb3oXkPTtrmbAGMUBpE",
                "dq"  : "mxRTU3QDyR2EnCv0Nl0TCF90oliJGAHR9HJmBe__EjuCBbwHfcT8OG3hWOv8vpzokQPRl5cQt3NckzX3fs6xlJN4Ai2Hh2zduKFVQ2p-AF2p6Yfahscjtq-GY9cB85NxLy2IXCC0PF--Sq9LOrTE9QV988SJy_yUrAjcZ5MmECk",
                "qi"  : "ldHXIrEmMZVaNwGzDF9WG8sHj2mOZmQpw9yrjLK9hAsmsNr5LTyqWAqJIYZSwPTYWhY4nu2O0EY9G9uYiqewXfCKw_UngrJt8Xwfq1Zruz0YY869zPN4GiE9-9rzdZB33RBw8kIOquY3MK74FMwCihYx_LiU2YTHkaoJ3ncvtvg"
            }
            """

        let keyCollection = try await JWTKeyCollection()
            .add(jwk: .init(json: privateKey))

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let data = try await keyCollection.sign(payload, kid: "1234")

        #expect(try await keyCollection.verify(data, as: TestPayload.self) == payload)
    }

    @Test("Test JWK Set")
    func testJWKS() async throws {
        let json = """
            {
                "keys": [
                    {"kty": "RSA", "alg": "RS256", "kid": "a", "n": "\(rsaModulus)", "e": "AQAB"},
                    {"kty": "RSA", "alg": "RS512", "kid": "b", "n": "\(rsaModulus)", "e": "AQAB"},
                ]
            }
            """

        let keyCollection = try await JWTKeyCollection().add(jwksJSON: json)

        await #expect(throws: Never.self) {
            try await keyCollection.getKey()
        }

        let a: JWTAlgorithm
        let b: JWTAlgorithm

        do {
            a = try await keyCollection.getKey(for: "a")
        } catch {
            Issue.record("Failed to get key a: \(error)")
            return
        }

        do {
            b = try await keyCollection.getKey(for: "b")
        } catch {
            Issue.record("Failed to get key b: \(error)")
            return
        }

        #expect(a.name == "RS256")
        #expect(b.name == "RS512")
    }

    @Test("Test Verification")
    func testVerification() async throws {
        struct NotBar: Error {
            let foo: String
        }
        struct Payload: JWTPayload {
            let foo: String
            func verify(using _: some JWTAlgorithm) throws {
                guard self.foo == "bar" else {
                    throw NotBar(foo: self.foo)
                }
            }
        }

        let keyCollection = await JWTKeyCollection().add(ecdsa: ES256PrivateKey())
        let token = try await keyCollection.sign(Payload(foo: "qux"))

        do {
            let payload = try await keyCollection.verify(token, as: Payload.self)
            #expect(payload.foo == "qux")
        } catch let error as NotBar {
            #expect(error.foo == "qux")
        }
    }

    @Test("Test JWK Set Verification without Alg field")
    func verifyWithJWKsWithoutAlg() async throws {
        // rsa key
        let modulus =
            "mSfWGBcXRBPgnwnL_ymDCkBaL6vcMcLpBEomzf-wZPajcQFiq4n4MHScyo85Te6GU-YuErVvHKK0D72JhMNWAQXbiF5Hh7swSYX9QsycWwHBgOBNfp51Fm_HTU7ikDBEdSonrmSep8wNqi_PX2_jVBsoxYNeiCQyDLFLHOAAcbIE4Y6lpJy76GpdHJscMO2RsUznjv5VPOQVa_BlQRIIZ0YoSsq9EEZna9O370wZy8jnOthQIXoegQ7sItS1JMKk4X5DdoRenIfbfWLy88XxKOPlIHA5ekT8TyzeI2Uqkg3YMETTDPrSROVO1Qdl2W1uMdfIZ94DgKpZN2VW-w0fLw"
        let exponent = "AQAB"
        let privateExponent =
            "awDmF9aqLqokmXjiydda8mKboArWwP2Ih7K3Ad3Og_u9nUp2gZrXiCMxGGSQiN5Jg3yiW_ffNYaHfyfRWKyQ_g31n4UfPLmPtw6iL3V9GChV5ZDRE9HpxE88U8r1h__xFFrrdnBeWKW8NldI70jg7vY6uiRae4uuXCfSbs4iAUxmRVKWCnV7JE6sObQKUV_EJkBcyND5Y97xsmWD0nPmXCnloQ84gF-eTErJoZBvQhJ4BhmBeUlREHmDKssaxVOCK4l335DKHD1vbuPk9e49M71BK7r2y4Atqk3TEetnwzMs3u-L9RqHaGIBw5u324uGweY7QeD7HFdAUtpjOq_MQQ"

        // sign jwt
        let keyCollection = try await JWTKeyCollection()
            .add(
                rsa: Insecure.RSA.PrivateKey(
                    modulus: modulus,
                    exponent: exponent,
                    privateExponent: privateExponent
                ),
                digestAlgorithm: .sha256,
                kid: "vapor"
            )
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: some JWTAlgorithm) throws {}
        }
        let jwt = try await keyCollection.sign(Foo(bar: 42), kid: "vapor")

        // verify using jwks without alg
        let jwksString = """
            {
                "keys": [
                    {
                        "kty": "RSA",
                        "use": "sig",
                        "kid": "vapor",
                        "n": "\(modulus)",
                        "e": "\(exponent)"
                    }
                ]
            }
            """

        try await keyCollection.add(jwksJSON: jwksString)
        let foo = try await keyCollection.verify(jwt, as: Foo.self)
        #expect(foo.bar == 42)
    }

    @Test("Test Microsoft JWKS")
    func addMicrosoftJWKS() async throws {
        await #expect(throws: Never.self) {
            try await JWTKeyCollection().add(jwksJSON: microsoftJWKS)
        }
    }

    @Test("Test Firebase JWT and Certificate")
    func addFirebaseJWTAndCertificate() async throws {
        let payload = try await JWTKeyCollection()
            .add(rsa: Insecure.RSA.PublicKey(certificatePEM: firebaseCert), digestAlgorithm: .sha256)
            .verify(firebaseJWT, as: FirebasePayload.self)
        #expect(payload.userID == "y8wiKThXGKM88xxrQWDZzKnBuqv2")
    }

    @Test("Test Custom JSON Coders")
    func customJSONCoders() async throws {
        let encoder = JSONEncoder()
        encoder.dateEncodingStrategy = .iso8601
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .iso8601

        let data =
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOiIyMDMzLTA1LTE4VDAzOjMzOjIwWiIsImFkbWluIjpmYWxzZSwibmFtZSI6IkZvbyIsInN1YiI6InZhcG9yIn0."
        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let keyCollection = await JWTKeyCollection()
            .addUnsecuredNone(
                parser: DefaultJWTParser(jsonDecoder: decoder),
                serializer: DefaultJWTSerializer(jsonEncoder: encoder)
            )
        let token = try await keyCollection.sign(payload)
        #expect(
            (token.split(separator: ".").dropFirst(1).first
                .map {
                    String(decoding: Data($0.utf8).base64URLDecodedBytes(), as: UTF8.self)
                } ?? "")
                .contains(#""exp":""#)
        )
        try await #expect(keyCollection.verify(token.bytes, as: TestPayload.self) == payload)
        try await #expect(keyCollection.verify(data.bytes, as: TestPayload.self) == payload)
        #expect(token.hasSuffix("."))
    }

    @Test("Test no key provided")
    func noKeyProvided() async throws {
        let keyCollection = JWTKeyCollection()
        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        await #expect(throws: JWTError.noKeyProvided) {
            _ = try await keyCollection.sign(payload)
        }
    }

    @Test("Test B64 Custom Serialising")
    func customSerialisingWithB64Header() async throws {
        struct CustomSerializer: JWTSerializer {
            var jsonEncoder: JWTJSONEncoder = .defaultForJWT

            func serialize(_ payload: some JWTPayload, header: JWTHeader) throws -> Data {
                if header.b64?.asBool == true {
                    try Data(self.jsonEncoder.encode(payload).base64URLEncodedBytes())
                } else {
                    try self.jsonEncoder.encode(payload)
                }
            }
        }

        struct CustomParser: JWTParser {
            var jsonDecoder: JWTJSONDecoder = .defaultForJWT

            func parse<Payload>(_ token: some DataProtocol, as _: Payload.Type) throws -> (
                header: JWTHeader, payload: Payload, signature: Data
            ) where Payload: JWTPayload {
                let (encodedHeader, encodedPayload, encodedSignature) = try getTokenParts(token)

                let header = try jsonDecoder.decode(
                    JWTHeader.self,
                    from: .init(encodedHeader.base64URLDecodedBytes())
                )

                let payload =
                    if header.b64?.asBool ?? true {
                        try self.jsonDecoder.decode(
                            Payload.self,
                            from: .init(encodedPayload.base64URLDecodedBytes())
                        )
                    } else {
                        try self.jsonDecoder.decode(Payload.self, from: .init(encodedPayload))
                    }

                let signature = Data(encodedSignature.base64URLDecodedBytes())

                return (header: header, payload: payload, signature: signature)
            }
        }

        let keyCollection = await JWTKeyCollection()
            .add(
                hmac: "secret",
                digestAlgorithm: .sha256,
                parser: CustomParser(),
                serializer: CustomSerializer()
            )

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let token = try await keyCollection.sign(payload, header: ["b64": true])
        let verified = try await keyCollection.verify(token, as: TestPayload.self)
        #expect(verified == payload)
    }

    @Test("Test JWK Encoding")
    func jwkEncoding() async throws {
        let jwkIdentifier = JWKIdentifier(string: "vapor")
        let data = try JSONEncoder().encode(jwkIdentifier)
        let string = String(data: data, encoding: .utf8)!
        #expect(string == "\"vapor\"")
    }

    @Test("Test parsing with wrong token")
    func parseWrongToken() async throws {
        let keyCollection = await JWTKeyCollection().addUnsecuredNone()

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let token = try await keyCollection.sign(payload)
        let parser = DefaultJWTParser()
        #expect(throws: Never.self) {
            try parser.parse(token.bytes, as: TestPayload.self)
        }

        // remove last "." from token
        let corruptedToken = String(token.dropLast())
        #expect(
            throws: JWTError.malformedToken(
                reason: "Couldn't decode JWT with error: \"Token is not split in 3 parts\""
            )
        ) {
            try parser.parse(corruptedToken.bytes, as: TestPayload.self)
        }
    }

    func testCustomHeaderFields() async throws {
        let keyCollection = await JWTKeyCollection().add(hmac: "secret", digestAlgorithm: .sha256)

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let customFields: JWTHeader = ["foo": "bar", "baz": 42]
        let token = try await keyCollection.sign(payload, header: customFields)

        let parsed = try DefaultJWTParser().parse(token.bytes, as: TestPayload.self)
        let foo = try #require(parsed.header.foo?.asString)
        let baz = try #require(parsed.header.baz?.asInt)
        #expect(foo == "bar")
        #expect(baz == 42)

        let encodedHeader = try JSONEncoder().encode(parsed.header)
        let jsonFields = """
            {
              "alg": "HS256",
              "typ": "JWT",
              "foo": "bar",
              "baz": 42
            }
            """

        let jsonDecoder = JSONDecoder()
        let decodedFields = try jsonDecoder.decode([String: JWTHeaderField].self, from: encodedHeader)
        let decodedJsonFields = try jsonDecoder.decode(
            [String: JWTHeaderField].self,
            from: jsonFields.data(using: .utf8)!
        )
        #expect(decodedFields == decodedJsonFields)
    }

    @Test("Test Custom Header Fields")
    func customHeaderFields() async throws {
        let keyCollection = await JWTKeyCollection()
            .add(
                hmac: .init(key: .init(size: .bits256)),
                digestAlgorithm: .sha384
            )

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        var commonFields = JWTHeader()
        commonFields.alg = "alg"
        commonFields.kid = "kid"
        commonFields.typ = "typ"
        commonFields.cty = "cty"
        commonFields.crit = ["crit"]
        commonFields.jku = "jku"
        commonFields.null = nil
        commonFields.bool = true
        commonFields.int = 21
        commonFields.decimal = 21.7
        commonFields.string = "test"
        commonFields.array = [.string("array_test")]
        commonFields.object = ["object_test": .string("object_test")]
        commonFields.x5u = "x5u"
        commonFields.x5t = "x5t"
        commonFields.x5tS256 = "x5tS256"
        let token = try await keyCollection.sign(payload, header: commonFields)

        let parsed = try DefaultJWTParser().parse(token.bytes, as: TestPayload.self)
        #expect(parsed.header.alg == "alg")
        #expect(parsed.header.kid == "kid")
        #expect(parsed.header.typ == "typ")
        #expect(parsed.header.cty == "cty")
        #expect(parsed.header.crit == ["crit"])
        #expect(parsed.header.jku == "jku")
        #expect(parsed.header.null?.isNull == true)
        #expect(parsed.header.bool?.asBool == true)
        #expect(parsed.header.int?.asInt == 21)
        #expect(parsed.header.decimal?.asDecimal == 21.7)
        #expect(parsed.header.string?.asString == "test")
        #expect(parsed.header.array?.asArray?.first?.asString == "array_test")
        #expect(try parsed.header.array?.asArray(of: String.self).first == "array_test")
        #expect(parsed.header.object?.asObject?["object_test"]?.asString == "object_test")
        #expect(parsed.header.x5u == "x5u")
        #expect(parsed.header.x5t == "x5t")
        #expect(parsed.header.x5tS256 == "x5tS256")
    }

    @Test("Test Custom Openbanking Header Fields")
    func sampleOpenbankingHeader() async throws {
        let keyCollection = await JWTKeyCollection().add(hmac: "secret", digestAlgorithm: .sha256)

        // https://openbanking.atlassian.net/wiki/spaces/DZ/pages/937656404/Read+Write+Data+API+Specification+-+v3.1
        let customFields: JWTHeader = [
            "kid": "90210ABAD",
            "http://openbanking.org.uk/iat": 1_501_497_671,
            "http://openbanking.org.uk/iss": "C=UK, ST=England, L=London, O=Acme Ltd.",
            "http://openbanking.org.uk/tan": "openbanking.org.uk",
            "crit": [
                "b64",
                "http://openbanking.org.uk/iat",
                "http://openbanking.org.uk/iss",
                "http://openbanking.org.uk/tan",
            ],
        ]

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let token = try await keyCollection.sign(payload, header: customFields)

        let parsed = try DefaultJWTParser().parse(token.bytes, as: TestPayload.self)
        let iat = parsed.header[dynamicMember: "http://openbanking.org.uk/iat"]?.asInt
        #expect(iat == 1_501_497_671)
        let iss = parsed.header[dynamicMember: "http://openbanking.org.uk/iss"]?.asString
        #expect(iss == "C=UK, ST=England, L=London, O=Acme Ltd.")
        let tan = parsed.header[dynamicMember: "http://openbanking.org.uk/tan"]?.asString
        #expect(tan == "openbanking.org.uk")
        #expect(
            parsed.header.crit == [
                "b64", "http://openbanking.org.uk/iat", "http://openbanking.org.uk/iss",
                "http://openbanking.org.uk/tan",
            ]
        )
        #expect(parsed.header.kid == "90210ABAD")
    }

    @Test("Test Signing with KID in Header")
    func signingWithKidInHeader() async throws {
        let key = ES256PrivateKey()

        let keyCollection = await JWTKeyCollection()
            .add(ecdsa: key, kid: "private")
            .add(ecdsa: key.publicKey, kid: "public")
        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        _ = try await keyCollection.sign(payload, header: ["kid": "private"])
        await #expect(throws: JWTError.self) {
            try await keyCollection.sign(payload, header: ["kid": "public"])
        }
        _ = try await keyCollection.sign(payload, kid: "private")
        await #expect(throws: JWTError.self) {
            try await keyCollection.sign(payload, kid: "public")
        }

        _ = try await keyCollection.sign(payload, kid: "private", header: ["kid": "public"])
        await #expect(throws: JWTError.self) {
            try await keyCollection.sign(payload, kid: "public", header: ["kid": "private"])
        }
    }

    @Test("Test Custom Object Header")
    func customObjectHeader() async throws {
        let keyCollection = await JWTKeyCollection().add(hmac: "secret", digestAlgorithm: .sha256)
        let customFields: JWTHeader = [
            "kid": "some-kid",
            "foo": ["bar": "baz"],
        ]

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let token = try await keyCollection.sign(payload, header: customFields)

        let parsed = try DefaultJWTParser().parse(token.bytes, as: TestPayload.self)
        let foo = try parsed.header.foo?.asObject(of: String.self)
        #expect(foo == ["bar": "baz"])
    }

    @Test("Test signing with iterating keys key collection")
    func testKeyCollectionIteration() async throws {
        let hmacToken = """
            eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6MjAwMDAwMDAwMH0.GW-OvOyauZXQeFuzFHRFL7saTXJrudGQ_qHtpbVWW9Y
            """
        let ecdsaToken = """
            eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6MjAwMDAwMDAwMH0.bxLwoupZk9MW5Ys650FNn1CpedHBOPKLf9dRVjmETs3KUn4VIfcxSIK7tOEEeuExgpKssRxYEMpLlFyY6jsLRg
            """

        let ecdsaPrivateKey = try ES256PrivateKey(
            pem: """
                -----BEGIN PRIVATE KEY-----
                MIGHAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBG0wawIBAQQgevZzL1gdAFr88hb2
                OF/2NxApJCzGCEDdfSp6VQO30hyhRANCAAQRWz+jn65BtOMvdyHKcvjBeBSDZH2r
                1RTwjmYSi9R/zpBnuQ4EiMnCqfMPWiZqB4QdbAd0E7oH50VpuZ1P087G
                -----END PRIVATE KEY-----
                """
        )

        let keyCollection = await JWTKeyCollection()
            .add(hmac: "secret", digestAlgorithm: .sha256, kid: "hmac")
            .add(ecdsa: ecdsaPrivateKey, kid: "ecdsa")

        let hmacVerified = try await keyCollection.verify(hmacToken, as: TestPayload.self)
        #expect(hmacVerified.sub == "1234567890")

        // The tokens don't have a KID, which means, since we're not iterating
        // over all the keys in the key collection, only the default (first added)
        // signer will be used.
        await #expect(throws: JWTError.signatureVerificationFailed) {
            try await keyCollection.verify(ecdsaToken, as: TestPayload.self)
        }

        let hmacIteratinglyVerified = try await keyCollection.verify(
            hmacToken,
            as: TestPayload.self,
            iteratingKeys: true
        )
        #expect(hmacIteratinglyVerified.sub == "1234567890")

        let ecdsaIteratinglyVerified = try await keyCollection.verify(
            ecdsaToken,
            as: TestPayload.self,
            iteratingKeys: true
        )
        #expect(ecdsaIteratinglyVerified.sub == "1234567890")
    }

    @Test("Test unverified string")
    func unverifiedString() async throws {
        let keyCollection = await JWTKeyCollection().addUnsecuredNone()

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let token = try await keyCollection.sign(payload)
        let unverified = try await keyCollection.unverified(token, as: TestPayload.self)

        #expect(unverified == payload)
    }

    @Test("Test unverified data")
    func unverifiedData() async throws {
        let keyCollection = await JWTKeyCollection().addUnsecuredNone()

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let token = try await keyCollection.sign(payload)
        let unverified = try await keyCollection.unverified(token.bytes, as: TestPayload.self)

        #expect(unverified == payload)
    }

    enum DummyError: Error {
        case dummy
    }

    @Test("Test JWT Error Description")
    func jwtErrorDescription() {
        #expect(
            JWTError.claimVerificationFailure(
                failedClaim: ExpirationClaim(value: .init(timeIntervalSince1970: 1)),
                reason: "test"
            )
            .description
                == "JWTKitError(errorType: claimVerificationFailure, failedClaim: JWTKit.ExpirationClaim(value: 1970-01-01 00:00:01 +0000), reason: \"test\")"
        )
        #expect(
            JWTError.signingAlgorithmFailure(DummyError.dummy).description
                == "JWTKitError(errorType: signingAlgorithmFailure, underlying: JWTKitTests.JWTKitTests.DummyError.dummy)"
        )
        #expect(
            JWTError.malformedToken(reason: "test").description
                == "JWTKitError(errorType: malformedToken, reason: \"test\")"
        )
        #expect(
            JWTError.signatureVerificationFailed.description
                == "JWTKitError(errorType: signatureVerificationFailed)"
        )
        #expect(
            JWTError.missingKIDHeader.description == "JWTKitError(errorType: missingKIDHeader)"
        )
        #expect(
            JWTError.unknownKID("test").description
                == "JWTKitError(errorType: unknownKID, kid: JWTKit.JWKIdentifier(string: \"test\"))"
        )
        #expect(
            JWTError.invalidJWK(reason: "test").description
                == "JWTKitError(errorType: invalidJWK, reason: \"test\")"
        )
        #expect(
            JWTError.invalidBool("test").description
                == "JWTKitError(errorType: invalidBool, name: \"test\")"
        )
        #expect(
            JWTError.noKeyProvided.description == "JWTKitError(errorType: noKeyProvided)"
        )
        #expect(
            JWTError.missingX5CHeader.description == "JWTKitError(errorType: missingX5CHeader)"
        )
        #expect(
            JWTError.invalidX5CChain(reason: "test").description
                == "JWTKitError(errorType: invalidX5CChain, reason: \"test\")"
        )
        #expect(
            JWTError.invalidHeaderField(reason: "test").description
                == "JWTKitError(errorType: invalidHeaderField, reason: \"test\")"
        )
        #expect(
            JWTError.generic(identifier: "id", reason: "test").description
                == "JWTKitError(errorType: generic, reason: \"test\")"
        )
    }

    @Test("Test removed header fields")
    func removeHeaderField() {
        var header = JWTHeader()

        header.field1 = "value1"
        header.field2 = "value2"

        #expect(header.fields.count == 2)

        header.remove("field1")

        #expect(header.fields.count == 1)
        #expect(header.field1 == nil)
        #expect(header.field2 == .string("value2"))
    }
}

let microsoftJWKS = """
    {
        "keys":[
            {
                "kty":"RSA",
                "use":"sig",
                "kid":"huN95IvPfehq34GzBDZ1GXGirnM",
                "x5t":"huN95IvPfehq34GzBDZ1GXGirnM",
                "n":"6lldKm5Rc_vMKa1RM_TtUv3tmtj52wLRrJqu13yGM3_h0dwru2ZP53y65wDfz6_tLCjoYuRCuVsjoW37-0zXUORJvZ0L90CAX-58lW7NcE4bAzA1pXv7oR9kQw0X8dp0atU4HnHeaTU8LZxcjJO79_H9cxgwa-clKfGxllcos8TsuurM8xi2dx5VqwzqNMB2s62l3MTN7AzctHUiQCiX2iJArGjAhs-mxS1wmyMIyOSipdodhjQWRAcseW-aFVyRTFVi8okl2cT1HJjPXdx0b1WqYSOzeRdrrLUcA0oR2Tzp7xzOYJZSGNnNLQqa9f6h6h52XbX0iAgxKgEDlRpbJw",
                "e":"AQAB",
                "x5c":[
                    "MIIDBTCCAe2gAwIBAgIQPCxFbySVSLZOggeWRzBWOjANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTIwMDYwNzAwMDAwMFoXDTI1MDYwNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAOpZXSpuUXP7zCmtUTP07VL97ZrY+dsC0ayartd8hjN/4dHcK7tmT+d8uucA38+v7Swo6GLkQrlbI6Ft+/tM11DkSb2dC/dAgF/ufJVuzXBOGwMwNaV7+6EfZEMNF/HadGrVOB5x3mk1PC2cXIyTu/fx/XMYMGvnJSnxsZZXKLPE7LrqzPMYtnceVasM6jTAdrOtpdzEzewM3LR1IkAol9oiQKxowIbPpsUtcJsjCMjkoqXaHYY0FkQHLHlvmhVckUxVYvKJJdnE9RyYz13cdG9VqmEjs3kXa6y1HANKEdk86e8czmCWUhjZzS0KmvX+oeoedl219IgIMSoBA5UaWycCAwEAAaMhMB8wHQYDVR0OBBYEFFXP0ODFhjf3RS6oRijM5Tb+yB8CMA0GCSqGSIb3DQEBCwUAA4IBAQB9GtVikLTbJWIu5x9YCUTTKzNhi44XXogP/v8VylRSUHI5YTMdnWwvDIt/Y1sjNonmSy9PrioEjcIiI1U8nicveafMwIq5VLn+gEY2lg6KDJAzgAvA88CXqwfHHvtmYBovN7goolp8TY/kddMTf6TpNzN3lCTM2MK4Ye5xLLVGdp4bqWCOJ/qjwDxpTRSydYIkLUDwqNjv+sYfOElJpYAB4rTL/aw3ChJ1iaA4MtXEt6OjbUtbOa21lShfLzvNRbYK3+ukbrhmRl9lemJEeUls51vPuIe+jg+Ssp43aw7PQjxt4/MpfNMS2BfZ5F8GVSVG7qNb352cLLeJg5rc398Z"
                ]
            },
            {
                "kty":"RSA",
                "use":"sig",
                "kid":"jibNbkFSSbmxPYrN9CFqRk4K4gw",
                "x5t":"jibNbkFSSbmxPYrN9CFqRk4K4gw",
                "n":"2YX-YDuuTzPiaiZKt04IuUzAjCjPLLmBCVA6npKuZyIouMuaSEuM7BP8QctfCprUY16Rq2-KDrAEvaaKJvsD5ZONddt79yFdCs1E8wKlYIPO74fSpePdVDizflr5W-QCFH9tokbZrHBBuluFojgtbvPMXAhHfZTGC4ItZ0i_Lc9eXwtENHJQC4e4m7olweK1ExM-OzsKGzDlOsOUOU5pN2sHY74nXPqQRH1dQKfB0NT0YrfkbnR8fiq8z-soixfECUXkF8FzWnMnqL6X90wngnuIi8OtH2mvDcnsvUVh3K2JgvSgjRWZbsDx6G-mVQL2vEuHXMXoIoe8hd1ZpV16pQ",
                "e":"AQAB",
                "x5c":[
                    "MIIDBTCCAe2gAwIBAgIQUUG7iptQUoVA7bYvX2tHlDANBgkqhkiG9w0BAQsFADAtMSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4XDTIwMDcxODAwMDAwMFoXDTI1MDcxODAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3VudHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBANmF/mA7rk8z4momSrdOCLlMwIwozyy5gQlQOp6SrmciKLjLmkhLjOwT/EHLXwqa1GNekatvig6wBL2miib7A+WTjXXbe/chXQrNRPMCpWCDzu+H0qXj3VQ4s35a+VvkAhR/baJG2axwQbpbhaI4LW7zzFwIR32UxguCLWdIvy3PXl8LRDRyUAuHuJu6JcHitRMTPjs7Chsw5TrDlDlOaTdrB2O+J1z6kER9XUCnwdDU9GK35G50fH4qvM/rKIsXxAlF5BfBc1pzJ6i+l/dMJ4J7iIvDrR9prw3J7L1FYdytiYL0oI0VmW7A8ehvplUC9rxLh1zF6CKHvIXdWaVdeqUCAwEAAaMhMB8wHQYDVR0OBBYEFFOUEOWLUJOTFTOlr7P+6GxsmM90MA0GCSqGSIb3DQEBCwUAA4IBAQCP+LLZw7SSYnWQmRGWHmksBwwJ4Gy32C6g7+wZZv3ombHW9mwLQuzsir97/PP042i/ZIxePHJavpeLm/z3KMSpGIPmiPtmgNcK4HtLTEDnoTprnllobOAqU0TREFWogjkockNo98AvpsmHxNMXuwDikto9o/d9ACBtpkpatS2xgVOZxZtqyMpwZzSJARD5A4qcKov4zdqntVyjpZGK4N6ZaedRbEVd12m1VI+dtDB9+EJRqtTn8zamPYljVTEPNCbDAFgKBDtrhwBnrrrnKTq4/LEOouNQZuUucBTMOGDn4FEejNh3qbxNdWR6tSZbXUnJ+NIQ99IqZMvvMqm9ndL7"
                ]
            },
            {
                "kty":"RSA",
                "use":"sig",
                "kid":"M6pX7RHoraLsprfJeRCjSxuURhc",
                "x5t":"M6pX7RHoraLsprfJeRCjSxuURhc",
                "n":"xHScZMPo8FifoDcrgncWQ7mGJtiKhrsho0-uFPXg-OdnRKYudTD7-Bq1MDjcqWRf3IfDVjFJixQS61M7wm9wALDj--lLuJJ9jDUAWTA3xWvQLbiBM-gqU0sj4mc2lWm6nPfqlyYeWtQcSC0sYkLlayNgX4noKDaXivhVOp7bwGXq77MRzeL4-9qrRYKjuzHfZL7kNBCsqO185P0NI2Jtmw-EsqYsrCaHsfNRGRrTvUHUq3hWa859kK_5uNd7TeY2ZEwKVD8ezCmSfR59ZzyxTtuPpkCSHS9OtUvS3mqTYit73qcvprjl3R8hpjXLb8oftfpWr3hFRdpxrwuoQEO4QQ",
                "e":"AQAB",
                "x5c":[
                    "MIIC8TCCAdmgAwIBAgIQfEWlTVc1uINEc9RBi6qHMjANBgkqhkiG9w0BAQsFADAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwHhcNMTgxMDE0MDAwMDAwWhcNMjAxMDE0MDAwMDAwWjAjMSEwHwYDVQQDExhsb2dpbi5taWNyb3NvZnRvbmxpbmUudXMwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDEdJxkw+jwWJ+gNyuCdxZDuYYm2IqGuyGjT64U9eD452dEpi51MPv4GrUwONypZF/ch8NWMUmLFBLrUzvCb3AAsOP76Uu4kn2MNQBZMDfFa9AtuIEz6CpTSyPiZzaVabqc9+qXJh5a1BxILSxiQuVrI2BfiegoNpeK+FU6ntvAZervsxHN4vj72qtFgqO7Md9kvuQ0EKyo7Xzk/Q0jYm2bD4SypiysJoex81EZGtO9QdSreFZrzn2Qr/m413tN5jZkTApUPx7MKZJ9Hn1nPLFO24+mQJIdL061S9LeapNiK3vepy+muOXdHyGmNctvyh+1+laveEVF2nGvC6hAQ7hBAgMBAAGjITAfMB0GA1UdDgQWBBQ5TKadw06O0cvXrQbXW0Nb3M3h/DANBgkqhkiG9w0BAQsFAAOCAQEAI48JaFtwOFcYS/3pfS5+7cINrafXAKTL+/+he4q+RMx4TCu/L1dl9zS5W1BeJNO2GUznfI+b5KndrxdlB6qJIDf6TRHh6EqfA18oJP5NOiKhU4pgkF2UMUw4kjxaZ5fQrSoD9omjfHAFNjradnHA7GOAoF4iotvXDWDBWx9K4XNZHWvD11Td66zTg5IaEQDIZ+f8WS6nn/98nAVMDtR9zW7Te5h9kGJGfe6WiHVaGRPpBvqC4iypGHjbRwANwofZvmp5wP08hY1CsnKY5tfP+E2k/iAQgKKa6QoxXToYvP7rsSkglak8N5g/+FJGnq4wP6cOzgZpjdPMwaVt5432GA=="
                ]
            }
        ]
    }
    """

let rsaModulus = """
    gWu7yhI35FScdKARYboJoAm-T7yJfJ9JTvAok_RKOJYcL8oLIRSeLqQX83PPZiWdKTdXaiGWntpDu6vW7VAb-HWPF6tNYSLKDSmR3sEu2488ibWijZtNTCKOSb_1iAKAI5BJ80LTqyQtqaKzT0XUBtMsde8vX1nKI05UxujfTX3kqUtkZgLv1Yk1ZDpUoLOWUTtCm68zpjtBrPiN8bU2jqCGFyMyyXys31xFRzz4MyJ5tREHkQCzx0g7AvW0ge_sBTPQ2U6NSkcZvQyDbfDv27cMUHij1Sjx16SY9a2naTuOgamjtUzyClPLVpchX-McNyS0tjdxWY_yRL9MYuw4AQ
    """

let rsaPrivateExponent = """
    L4z0tz7QWE0aGuOA32YqCSnrSYKdBTPFDILCdfHonzfP7WMPibz4jWxu_FzNk9s4Dh-uN2lV3NGW10pAsnqffD89LtYanRjaIdHnLW_PFo5fEL2yltK7qMB9hO1JegppKCfoc79W4-dr-4qy1Op0B3npOP-DaUYlNamfDmIbQW32UKeJzdGIn-_ryrBT7hQW6_uHLS2VFPPk0rNkPPKZYoNaqGnJ0eaFFF-dFwiThXIpPz--dxTAL8xYf275rjG8C9lh6awOfJSIdXMVuQITWf62E0mSQPR2-219bShMKriDYcYLbT3BJEgOkRBBHGuHo9R5TN298anxZqV1u5jtUQ
    """

struct FirebasePayload: JWTPayload, Equatable {
    enum CodingKeys: String, CodingKey {
        case providerID = "provider_id"
        case issuer = "iss"
        case audience = "aud"
        case authTime = "auth_time"
        case userID = "user_id"
        case subject = "sub"
        case issuedAt = "iat"
        case expiration = "exp"
    }

    let providerID: String
    let issuer: IssuerClaim
    let audience: AudienceClaim
    let authTime: Int
    let userID: String
    let subject: SubjectClaim
    let issuedAt: IssuedAtClaim
    let expiration: ExpirationClaim

    func verify(using _: some JWTAlgorithm) throws {
        try self.expiration.verifyNotExpired(currentDate: .distantPast)
    }
}

let firebaseJWT = """
    eyJhbGciOiJSUzI1NiIsImtpZCI6IjU1NGE3NTQ3Nzg1ODdjOTRjMTY3M2U4ZWEyNDQ2MTZjMGMwNDNjYmMiLCJ0eXAiOiJKV1QifQ.eyJwcm92aWRlcl9pZCI6ImFub255bW91cyIsImlzcyI6Imh0dHBzOi8vc2VjdXJldG9rZW4uZ29vZ2xlLmNvbS92enNnLXNjaGVkdWxlLXRlc3QiLCJhdWQiOiJ2enNnLXNjaGVkdWxlLXRlc3QiLCJhdXRoX3RpbWUiOjE1OTYyMzg5ODIsInVzZXJfaWQiOiJ5OHdpS1RoWEdLTTg4eHhyUVdEWnpLbkJ1cXYyIiwic3ViIjoieTh3aUtUaFhHS004OHh4clFXRFp6S25CdXF2MiIsImlhdCI6MTU5NjIzODk4MiwiZXhwIjoxNTk2MjQyNTgyLCJmaXJlYmFzZSI6eyJpZGVudGl0aWVzIjp7fSwic2lnbl9pbl9wcm92aWRlciI6ImFub255bW91cyJ9fQ.vW5N3RqN8ba_P56GgjyMY-RE3hr_ciEw-E_oBtVjMJw3pgIO7MDHj0eRqTDTbjapN0BhkxTjkOA-L5pGO-9uA7afO-45vmiyaFDaN_oIYHNCewDgVaphDy_CYQ1PJugZHVjumk-qgzdS9nen_6oXmWZ1CYMop-g8UEyVHUaU-yjnvYSvvRWcas--HaErcsPY6uDx9DR8R2_mC-_VHBD58zN1svjTELkeVIZtkvA2Pxy1WO1NKxc0hWiz7w6RTu6P56_DJ1OqyMwxQavblaufdjccuC3bnv_MGKM8xhtsYLFWPnwFD762A50cHyS6SondruP7UnFQc1owlB6gaxEihw
    """

let firebaseCert = """
    -----BEGIN CERTIFICATE-----
    MIIDHDCCAgSgAwIBAgIIOvZ+ZDrIgmQwDQYJKoZIhvcNAQEFBQAwMTEvMC0GA1UE
    AxMmc2VjdXJldG9rZW4uc3lzdGVtLmdzZXJ2aWNlYWNjb3VudC5jb20wHhcNMjAw
    NzI0MDkyMDAxWhcNMjAwODA5MjEzNTAxWjAxMS8wLQYDVQQDEyZzZWN1cmV0b2tl
    bi5zeXN0ZW0uZ3NlcnZpY2VhY2NvdW50LmNvbTCCASIwDQYJKoZIhvcNAQEBBQAD
    ggEPADCCAQoCggEBANSBPQydBvIITxwMsm0adXL5ToKR6Aihi3fCepGZj1Oq2pdq
    r9ObfFcDX4GKHF7w6pm8WXxoZnjO37waSJc1ECmZt11tR0Ei/f0huLqDqNItGWRc
    ApogR3Af8C12IwFbxvp5tPj4s8H7Ldnrr97zzXogrTKvQCVJQJE43SfqcOO0T1br
    gfskj+G863Uy5JN7S8OijDLFK3YGIIvQDv6jp0tVrRwUUedJ4qET3IVWLkW5jAcd
    WAy7/RmIVVZFXuqjyunU6xNd6gLw5uZPZdLjSW9CccFmZQfinuNKyFGLhdF00TMq
    Torq8EOjFanRbxRi3mb9g01hVKY8WcsK1CE4RCMCAwEAAaM4MDYwDAYDVR0TAQH/
    BAIwADAOBgNVHQ8BAf8EBAMCB4AwFgYDVR0lAQH/BAwwCgYIKwYBBQUHAwIwDQYJ
    KoZIhvcNAQEFBQADggEBAGMRck+Afw3zQF3SqgJ80bCgFJy4CidQuoNuElA673Y+
    H4ulR5n/UV3feelR2+q0PvbZIVNf3Y5Yt+AWK9uK3LPprouFnx4U2X+mxsLHlHUC
    Kl+wKoLuDvAmiDHu5JIjoYO0el6JJYNVnG3wCrSLLc6ehA32hfngdtJmkDN0/OoM
    xmbj7X3JWctiJw0NxmH8wrKbeZLVIsaCwfc8iKjwcqRyA6hUxTobcsNs3IZsYv2W
    g/5ZupoI8k2foTq4OdXJH/hkq4N5AyLp9S/RSodW6X+gexxohtgJxGx0gojotMzX
    sb7NLsl7DkvjjxTz7I98xaGbfhofgYympeKT6UO+tmc=
    -----END CERTIFICATE-----
    """
#endif  // canImport(Testing)
