import XCTest
#if os(Linux)
import FoundationNetworking
#endif
@testable import JWTKit

class JWTKitTests: XCTestCase {
    func testGettingStarted() throws {
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
            func verify(using signer: JWTSigner) throws {
                try self.expiration.verifyNotExpired()
            }
        }

        let signers = JWTSigners()
        signers.use(.hs256(key: "secret"))

        do {
            let jwt = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YXBvciIsImV4cCI6NjQwOTIyMTEyMDAsImFkbWluIjp0cnVlfQ.lS5lpwfRNSZDvpGQk6x5JI1g40gkYCOWqbc3J_ghowo"
            let payload = try signers.verify(jwt, as: TestPayload.self)
            XCTAssertEqual(payload.admin, true)
        }

        do {
            let payload = TestPayload(
                subject: "vapor",
                expiration: .init(value: .distantFuture),
                admin: true
            )
            let jwt = try signers.sign(payload)
            print(jwt)
        }
    }

    func testJWKsApple() throws {
        // Download the JWKS.
        // This could be done asynchronously if needed.
        let jwksData = try Data(
            contentsOf: URL(string: "https://appleid.apple.com/auth/keys")!
        )

        // Decode the downloaded JSON.
        let jwks = try JSONDecoder().decode(JWKS.self, from: jwksData)

        // Create signers and add JWKS.
        let signers = JWTSigners()
        try signers.use(jwks: jwks)
    }

    func testRSADocs() throws {
        let signers = JWTSigners()
        try signers.use(.rs256(key: .public(pem: rsaPublicKey)))
    }

    func testECDSADocs() throws {
        let signers = JWTSigners()
        try signers.use(.es256(key: .public(pem: ecdsaPublicKey)))
    }

    func testClaimDocs() throws {
        struct TestPayload: JWTPayload {
            enum CodingKeys: String, CodingKey {
                case audience = "aud"
            }

            var audience: AudienceClaim

            func verify(using signer: JWTSigner) throws {
                try self.audience.verifyIntendedAudience(includes: "foo")
            }
        }
    }

    func testParse() throws {
        let data = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6OTk5OTk5OTk5OTk5fQ.Ks7KcdjrlUTYaSNeAO5SzBla_sFCHkUh4vvJYn6q29U"

        let test = try JWTSigner.hs256(key: "secret".bytes)
            .verify(data, as: TestPayload.self)
        XCTAssertEqual(test.name, "John Doe")
        XCTAssertEqual(test.sub.value, "1234567890")
        XCTAssertEqual(test.admin, true)
    }

    func testExpired() throws {
        let data = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6MX0.-x_DAYIg4R4R9oZssqgWyJP_oWO1ESj8DgKrGCk7i5o"

        do {
            _ = try JWTSigner.hs256(key: "secret".bytes)
                .verify(data, as: TestPayload.self)
        } catch let error as JWTError {
            switch error {
            case .claimVerificationFailure(let name, _):
                XCTAssertEqual(name, "exp")
            default:
                XCTFail("wrong error")
            }
        }
    }

    func testExpirationDecoding() throws {
        let data = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJleHAiOjIwMDAwMDAwMDB9.JgCO_GqUQnbS0z2hCxJLE9Tpt5SMoZObHBxzGBWuTYQ"

        let test = try JWTSigner.hs256(key: "secret".bytes)
            .verify(data, as: ExpirationPayload.self)
        XCTAssertEqual(test.exp.value, Date(timeIntervalSince1970: 2_000_000_000))
    }

    func testExpirationEncoding() throws {
        let exp = ExpirationClaim(value: Date(timeIntervalSince1970: 2_000_000_000))
        let jwt = try JWTSigner.hs256(key: "secret".bytes)
            .sign(ExpirationPayload(exp: exp))
        let parser = try JWTParser(token: jwt.bytes)
        try XCTAssertEqual(parser.header().typ, "JWT")
        try XCTAssertEqual(parser.header().alg, "HS256")
        try XCTAssertEqual(parser.payload(as: ExpirationPayload.self).exp, exp)
        try parser.verify(using: .hs256(key: "secret".bytes))
    }

    func testSigners() throws {
        let data = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCIsImtpZCI6ImZvbyJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImV4cCI6OTk5OTk5OTk5OTk5OTl9.Gf7leJ8i30LmMI7GBTpWDMXV60y1wkTOCOBudP9v9ms"
        let signers = JWTSigners()
        signers.use(.hs256(key: "bar".bytes), kid: "foo")
        let payload = try signers.verify(data, as: TestPayload.self)
        XCTAssertEqual(payload.name, "John Doe")
    }
    
    func testUnsecuredNone() throws {
        let data =
            "eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0.eyJleHAiOjIwMDAwMDAwMDAsImFkbWluIjpmYWxzZSwibmFtZSI6IkZvbyIsInN1YiI6InZhcG9yIn0."
        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let signer = JWTSigner.unsecuredNone
        let token = try signer.sign(payload)
        try XCTAssertEqual(signer.verify(token.bytes, as: TestPayload.self), payload)
        try XCTAssertEqual(signer.verify(data.bytes, as: TestPayload.self), payload)
        XCTAssertTrue(token.hasSuffix("."))
    }

    func testRSA() throws {
        let privateSigner = try JWTSigner.rs256(key: .private(pem: rsaPrivateKey.bytes))
        let publicSigner = try JWTSigner.rs256(key: .public(pem: rsaPublicKey.bytes))

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let privateSigned = try privateSigner.sign(payload)
        try XCTAssertEqual(publicSigner.verify(privateSigned.bytes, as: TestPayload.self), payload)
        try XCTAssertEqual(privateSigner.verify(privateSigned.bytes, as: TestPayload.self), payload)
    }

    func testRSASignWithPublic() throws {
        let publicSigner = try JWTSigner.rs256(key: .public(pem: rsaPublicKey.bytes))
        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        do {
            _ = try publicSigner.sign(payload)
            XCTFail("cannot sign with public signer")
        } catch {
            // pass
        }
    }

    func testECDSAGenerate() throws {
        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let signer = try JWTSigner.es256(key: .generate())
        let token = try signer.sign(payload)
        try XCTAssertEqual(signer.verify(token, as: TestPayload.self), payload)
    }

    func testECDSAPublicPrivate() throws {
        let publicSigner = try JWTSigner.es256(key: .public(pem: ecdsaPublicKey.bytes))
        let privateSigner = try JWTSigner.es256(key: .private(pem: ecdsaPrivateKey.bytes))

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        for _ in 0..<1_000 {
            let token = try privateSigner.sign(payload)
            // test private signer decoding
            try XCTAssertEqual(privateSigner.verify(token, as: TestPayload.self), payload)
            // test public signer decoding
            try XCTAssertEqual(publicSigner.verify(token, as: TestPayload.self), payload)
        }
    }
    
    func testGetECParametersP256() throws {
        let message = "test".bytes

        let ec = try ECDSAKey.generate(curve: .p256)
        let ecSigner = JWTSigner.es256(key: ec)

        let signature = try ecSigner.algorithm.sign(message)

        let params = ec.parameters!
        let ecVerifier = try JWTSigner.es256(key: ECDSAKey(parameters: params, curve: .p256))
        XCTAssertTrue(try ecVerifier.algorithm.verify(signature, signs: message))
        XCTAssertEqual(ec.curve, .p256)
    }
    
    func testGetECParametersP384() throws {
        let message = "test".bytes

        let ec = try ECDSAKey.generate(curve: .p384)
        let ecSigner = JWTSigner.es384(key: ec)

        let signature = try ecSigner.algorithm.sign(message)

        let params = ec.parameters!
        let ecVerifier = try JWTSigner.es384(key: ECDSAKey(parameters: params, curve: .p384))
        XCTAssertTrue(try ecVerifier.algorithm.verify(signature, signs: message))
        XCTAssertEqual(ec.curve, .p384)
    }
    
    func testGetECParametersP521() throws {
        let message = "test".bytes

        let ec = try ECDSAKey.generate(curve: .p521)
        let ecSigner = JWTSigner.es512(key: ec)

        let signature = try ecSigner.algorithm.sign(message)

        let params = ec.parameters!
        let ecVerifier = try JWTSigner.es512(key: ECDSAKey(parameters: params, curve: .p521))
        XCTAssertTrue(try ecVerifier.algorithm.verify(signature, signs: message))
        XCTAssertEqual(ec.curve, .p521)
    }
    
    func testVerifyingECDSAKeyUsingJWK() throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using signer: JWTSigner) throws { }
        }
                
        // ecdsa key
        let x = "0tu/H2ShuV8RIgoOxFneTdxmQQYsSk5LdCPuEIBXT+hHd0ufc/OwjEbqilsYnTdm"
        let y = "RWRZz+tP83N0CGwroGyFVgH3PYAO6Oewpu4Xf6EXCp4+sU8uWegwjd72sBK6axj7"
        
        let privateKey = "k+1LAHQRSSMcyaouYK0YOzRbUKj6ISnvihO2XdLQZHQgMt9BkuCT0+539FSHmJxg"

        // sign jwt
        let privateSigner = JWTSigner.es384(key: try ECDSAKey(parameters: .init(x: x, y: y), curve: .p384, privateKey: privateKey))
        
        let jwt = try privateSigner.sign(Foo(bar: 42), kid: "vapor")

        // verify using jwks without alg
        let jwksString = """
        {
            "keys": [
                {
                    "kty": "EC",
                    "use": "sig",
                    "kid": "vapor",
                    "x": "\(x)",
                    "y": "\(y)"
                 }
            ]
        }
        """

        let signers = JWTSigners()
        try signers.use(jwksJSON: jwksString)
        let foo = try signers.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }

    func testVerifyingECDSAKeyUsingJWKBase64URL() throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using signer: JWTSigner) throws { }
        }
                
        // ecdsa key in base64url format
        let x = "0tu_H2ShuV8RIgoOxFneTdxmQQYsSk5LdCPuEIBXT-hHd0ufc_OwjEbqilsYnTdm"
        let y = "RWRZz-tP83N0CGwroGyFVgH3PYAO6Oewpu4Xf6EXCp4-sU8uWegwjd72sBK6axj7"
        
        let privateKey = "k-1LAHQRSSMcyaouYK0YOzRbUKj6ISnvihO2XdLQZHQgMt9BkuCT0-539FSHmJxg"

        // sign jwt
        let privateSigner = JWTSigner.es384(key: try ECDSAKey(parameters: .init(x: x, y: y), curve: .p384, privateKey: privateKey))
        
        let jwt = try privateSigner.sign(Foo(bar: 42), kid: "vapor")

        // verify using jwks without alg
        let jwksString = """
        {
            "keys": [
                {
                    "kty": "EC",
                    "use": "sig",
                    "kid": "vapor",
                    "x": "\(x)",
                    "y": "\(y)"
                 }
            ]
        }
        """

        let signers = JWTSigners()
        try signers.use(jwksJSON: jwksString)
        let foo = try signers.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }

    func testVerifyingECDSAKeyUsingJWKWithMixedBase64Formats() throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using signer: JWTSigner) throws { }
        }
                
        // ecdsa key in base64url format
        let x = "0tu_H2ShuV8RIgoOxFneTdxmQQYsSk5LdCPuEIBXT-hHd0ufc_OwjEbqilsYnTdm"
        let y = "RWRZz-tP83N0CGwroGyFVgH3PYAO6Oewpu4Xf6EXCp4-sU8uWegwjd72sBK6axj7"
        
        // private key in base64 format
        let privateKey = "k+1LAHQRSSMcyaouYK0YOzRbUKj6ISnvihO2XdLQZHQgMt9BkuCT0+539FSHmJxg"

        // sign jwt
        let privateSigner = JWTSigner.es384(key: try ECDSAKey(parameters: .init(x: x, y: y), curve: .p384, privateKey: privateKey))
        
        let jwt = try privateSigner.sign(Foo(bar: 42), kid: "vapor")

        // verify using jwks without alg
        let jwksString = """
        {
            "keys": [
                {
                    "kty": "EC",
                    "use": "sig",
                    "kid": "vapor",
                    "x": "\(x)",
                    "y": "\(y)"
                 }
            ]
        }
        """

        let signers = JWTSigners()
        try signers.use(jwksJSON: jwksString)
        let foo = try signers.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }
    
    func testJWTioExample() throws {
        let token = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HWP_3cYHBw7AhHale5wky6-sVA"
        let corruptedToken = "eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWUsImlhdCI6MTUxNjIzOTAyMn0.tyh-VfuzIxCyGYDlkBA7DfyjrqmSHu6pQ2hoZuFqUSLPNY2N0mpHb3nk5K17HwP_3cYHBw7AhHale5wky6-sVA"

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

            func verify(using signer: JWTSigner) throws {
                // no verifiable claims
            }
        }

        // create public key signer (verifier)
        let publicSigner = try JWTSigner.es256(key: .public(pem: publicKey.bytes))

        // decode jwt and test payload contents
        let jwt = try publicSigner.verify(token, as: JWTioPayload.self)
        XCTAssertEqual(jwt.sub, "1234567890")
        XCTAssertEqual(jwt.name, "John Doe")
        XCTAssertEqual(jwt.admin, true)
        XCTAssertEqual(jwt.iat.value, .init(timeIntervalSince1970: 1516239022))

        // test corrupted token
        // this should fail
        do {
            _ = try publicSigner.verify(corruptedToken, as: JWTioPayload.self)
        } catch let error as JWTError {
            switch error {
            case .signatureVerifictionFailed:
                // pass
                XCTAssert(true)
            default:
                XCTFail("unexpected error: \(error)")
            }
        }
    }
    
    func testJWKSigner() throws {
        let privateKey = """
        {
            "kty": "RSA",
            "d": "\(rsaPrivateExponent)",
            "e": "AQAB",
            "use": "sig",
            "kid": "1234",
            "alg": "RS256",
            "n": "\(rsaModulus)"
        }
        """

        let publicKey = """
        {
            "kty": "RSA",
            "e": "AQAB",
            "use": "sig",
            "kid": "1234",
            "alg": "RS256",
            "n": "\(rsaModulus)"
        }
        """

        let publicSigners = JWTSigners()
        try publicSigners.use(jwk: .init(json: publicKey))

        let privateSigners = JWTSigners()
        try privateSigners.use(jwk: .init(json: privateKey))

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let data = try privateSigners.sign(payload, kid: "1234")
        // test private signer decoding
        try XCTAssertEqual(privateSigners.verify(data, as: TestPayload.self), payload)
        // test public signer decoding
        try XCTAssertEqual(publicSigners.verify(data, as: TestPayload.self), payload)
    }
    
    func testJWKS() throws {
        let json = """
        {
            "keys": [
                {"kty": "RSA", "alg": "RS256", "kid": "a", "n": "\(rsaModulus)", "e": "AQAB"},
                {"kty": "RSA", "alg": "RS512", "kid": "b", "n": "\(rsaModulus)", "e": "AQAB"},
            ]
        }
        """
        
        let signers = JWTSigners()
        try signers.use(jwksJSON: json)

        XCTAssertNotNil(signers.get())
        guard let a = signers.get(kid: "a") else {
            XCTFail("expected signer a")
            return
        }
        guard let b = signers.get(kid: "b") else {
            XCTFail("expected signer b")
            return
        }
        XCTAssertEqual(a.algorithm.name, "RS256")
        XCTAssertEqual(b.algorithm.name, "RS512")
    }

    func testJWTPayloadVerification() throws {
        struct NotBar: Error {
            let foo: String
        }
        struct Payload: JWTPayload {
            let foo: String
            func verify(using signer: JWTSigner) throws {
                guard self.foo == "bar" else {
                    throw NotBar(foo: self.foo)
                }
            }
        }

        let signer = try JWTSigner.es256(key: .generate())
        do {
            let token = try signer.sign(Payload(foo: "qux"))
            _ = try signer.verify(token, as: Payload.self)
        } catch let error as NotBar {
            XCTAssertEqual(error.foo, "qux")
        }
        do {
            let token = try signer.sign(Payload(foo: "bar"))
            let payload = try signer.verify(token, as: Payload.self)
            XCTAssertEqual(payload.foo, "bar")
        }
    }

    func testBoolClaim() throws {
        let str = #"{"trueStr":"true","trueBool":true,"falseStr":"false","falseBool":false}"#
        var data = str.data(using: .utf8)!
        let decoded = try! JSONDecoder().decode(BoolPayload.self, from: data)

        XCTAssertTrue(decoded.trueStr.value)
        XCTAssertTrue(decoded.trueBool.value)
        XCTAssertFalse(decoded.falseBool.value)
        XCTAssertFalse(decoded.falseStr.value)

        data = #"{"bad":"Not boolean"}"#.data(using: .utf8)!
        XCTAssertThrowsError(try JSONDecoder().decode(BoolPayload.self, from: data))
    }

    func testLocaleClaim() throws {
        let ptBR = #"{"locale":"pt-BR"}"#

        let plainEnglish = try LocalePayload.from(#"{"locale":"en"}"#)
        let brazillianPortugese = try LocalePayload.from(ptBR)
        let nadizaDialectSlovenia = try LocalePayload.from(#"{"locale":"sl-nedis"}"#)
        let germanSwissPost1996 = try LocalePayload.from(#"{"locale":"de-CH-1996"}"#)
        let chineseTraditionalTwoPrivate = try LocalePayload.from(#"{"locale":"zh-Hant-CN-x-private1-private2"}"#)

        XCTAssertEqual(plainEnglish.locale.value.identifier, "en")
        XCTAssertEqual(brazillianPortugese.locale.value.identifier, "pt-BR")
        XCTAssertEqual(nadizaDialectSlovenia.locale.value.identifier, "sl-nedis")
        XCTAssertEqual(germanSwissPost1996.locale.value.identifier, "de-CH-1996")
        XCTAssertEqual(chineseTraditionalTwoPrivate.locale.value.identifier, "zh-Hant-CN-x-private1-private2")

        let encoded = try JSONEncoder().encode(brazillianPortugese)
        let string = String(bytes: encoded, encoding: .utf8)!
        XCTAssertEqual(string, ptBR)
    }
    
    func testSingleAudienceClaim() throws {
        let id = UUID()
        let str = "{\"audience\":\"\(id.uuidString)\"}"
        let data = str.data(using: .utf8)!
        let decoded = try! JSONDecoder().decode(AudiencePayload.self, from: data)
        
        XCTAssertEqual(decoded.audience.value, [id.uuidString])
        XCTAssertNoThrow(try decoded.audience.verifyIntendedAudience(includes: id.uuidString))
        XCTAssertThrowsError(try decoded.audience.verifyIntendedAudience(includes: UUID().uuidString)) {
            guard let jwtError = try? XCTUnwrap($0 as? JWTError) else { return }
            guard case let .claimVerificationFailure(name, _) = jwtError else {
                XCTFail("Unexpectedly got \(jwtError) instead of claim verification failure.")
                return
            }
            XCTAssertEqual(name, "aud")
        }
    }

    func testMultipleAudienceClaim() throws {
        let id1 = UUID(), id2 = UUID()
        let str = "{\"audience\":[\"\(id1.uuidString)\", \"\(id2.uuidString)\"]}"
        let data = str.data(using: .utf8)!
        let decoded = try! JSONDecoder().decode(AudiencePayload.self, from: data)
        
        XCTAssertEqual(decoded.audience.value, [id1.uuidString, id2.uuidString])
        XCTAssertNoThrow(try decoded.audience.verifyIntendedAudience(includes: id1.uuidString))
        XCTAssertNoThrow(try decoded.audience.verifyIntendedAudience(includes: id2.uuidString))
        XCTAssertThrowsError(try decoded.audience.verifyIntendedAudience(includes: UUID().uuidString)) {
            guard let jwtError = try? XCTUnwrap($0 as? JWTError) else { return }
            guard case let .claimVerificationFailure(name, _) = jwtError else {
                XCTFail("Unexpectedly got \(jwtError) instead of claim verification failure.")
                return
            }
            XCTAssertEqual(name, "aud")
        }
    }

    func testAlgorithmInJWTHeaderOnly() throws {
        // rsa key
        let modulus = "mSfWGBcXRBPgnwnL_ymDCkBaL6vcMcLpBEomzf-wZPajcQFiq4n4MHScyo85Te6GU-YuErVvHKK0D72JhMNWAQXbiF5Hh7swSYX9QsycWwHBgOBNfp51Fm_HTU7ikDBEdSonrmSep8wNqi_PX2_jVBsoxYNeiCQyDLFLHOAAcbIE4Y6lpJy76GpdHJscMO2RsUznjv5VPOQVa_BlQRIIZ0YoSsq9EEZna9O370wZy8jnOthQIXoegQ7sItS1JMKk4X5DdoRenIfbfWLy88XxKOPlIHA5ekT8TyzeI2Uqkg3YMETTDPrSROVO1Qdl2W1uMdfIZ94DgKpZN2VW-w0fLw"
        let exponent = "AQAB"
        let privateExponent = "awDmF9aqLqokmXjiydda8mKboArWwP2Ih7K3Ad3Og_u9nUp2gZrXiCMxGGSQiN5Jg3yiW_ffNYaHfyfRWKyQ_g31n4UfPLmPtw6iL3V9GChV5ZDRE9HpxE88U8r1h__xFFrrdnBeWKW8NldI70jg7vY6uiRae4uuXCfSbs4iAUxmRVKWCnV7JE6sObQKUV_EJkBcyND5Y97xsmWD0nPmXCnloQ84gF-eTErJoZBvQhJ4BhmBeUlREHmDKssaxVOCK4l335DKHD1vbuPk9e49M71BK7r2y4Atqk3TEetnwzMs3u-L9RqHaGIBw5u324uGweY7QeD7HFdAUtpjOq_MQQ"

        // sign jwt
        let privateSigner = JWTSigner.rs256(key: RSAKey(
            modulus: modulus,
            exponent: exponent,
            privateExponent: privateExponent
        )!)
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using signer: JWTSigner) throws { }
        }
        let jwt = try privateSigner.sign(Foo(bar: 42), kid: "vapor")

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

        let signers = JWTSigners()
        try signers.use(jwksJSON: jwksString)
        let foo = try signers.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }

    func testMicrosoftJWKs() throws {
        let signers = JWTSigners()
        try signers.use(jwksJSON: microsoftJWKS)
    }

    func testRSACertificate() throws {
        let test = TestPayload(
            sub: "vapor",
            name: "foo",
            admin: true,
            exp: .init(value: .distantFuture)
        )
        let jwt = try JWTSigner.rs256(
            key: .private(pem: rsa2PrivateKey)
        ).sign(test)

        let payload = try JWTSigner.rs256(
            key: .certificate(pem: rsa2Cert)
        ).verify(jwt, as: TestPayload.self)
        XCTAssertEqual(payload, test)
    }

    func testFirebaseJWTAndCertificate() throws {
        let payload = try JWTSigner.rs256(key: .certificate(pem: firebaseCert))
            .verify(firebaseJWT, as: FirebasePayload.self)
        XCTAssertEqual(payload.userID, "y8wiKThXGKM88xxrQWDZzKnBuqv2")
    }
    
    // MARK: - EdDSA
    
    func testEdDSAGenerate() throws {
        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        
        let signer = try JWTSigner.eddsa(.generate(curve: .ed25519))
        let token = try signer.sign(payload)
        try XCTAssertEqual(signer.verify(token, as: TestPayload.self), payload)
    }
    
    func testEdDSAPublicPrivate() throws {
        
        let publicSigner = try JWTSigner.eddsa(
            .public(x: eddsaPublicKeyBase64, curve: .ed25519)
        )
        let privateSigner = try JWTSigner.eddsa(
            .private(x: eddsaPublicKeyBase64, d: eddsaPrivateKeyBae64, curve: .ed25519)
        )

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        for _ in 0..<1_000 {
            let token = try privateSigner.sign(payload)
            // test public signer decoding
            try XCTAssertEqual(publicSigner.verify(token, as: TestPayload.self), payload)
        }
    }
        
    func testVerifyingEdDSAKeyUsingJWK() throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using signer: JWTSigner) throws { }
        }
                
        // ecdsa key in base64 format
        let x = eddsaPublicKeyBase64
        let d = eddsaPrivateKeyBae64
        
        // sign jwt
        let signer = try JWTSigner.eddsa(.private(x: x, d: d, curve: .ed25519))
        let jwt = try signer.sign(Foo(bar: 42), kid: "vapor")

        // verify using jwks
        let jwksString = """
        {
            "keys": [
                {
                    "kty": "OKP",
                    "crv": "Ed25519",
                    "use": "sig",
                    "kid": "vapor",
                    "x": "\(x)",
                    "d": "\(d)"
                 }
            ]
        }
        """

        let signers = JWTSigners()
        try signers.use(jwksJSON: jwksString)
        let foo = try signers.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }
    
    func testVerifyingEdDSAKeyUsingJWKBase64URL() throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using signer: JWTSigner) throws { }
        }
                
        // eddsa key in base64url format
        let x = eddsaPublicKeyBase64Url
        let d = eddsaPrivateKeyBae64Url

        // sign jwt
        let signer = try JWTSigner.eddsa(.private(x: x, d: d, curve: .ed25519))
        let jwt = try signer.sign(Foo(bar: 42), kid: "vapor")

        // verify using jwks without alg
        let jwksString = """
        {
            "keys": [
                {
                 "kty": "OKP",
                 "crv": "Ed25519",
                 "use": "sig",
                 "kid": "vapor",
                 "x": "\(x)",
                 "d": "\(d)"
                 }
            ]
        }
        """

        let signers = JWTSigners()
        try signers.use(jwksJSON: jwksString)
        let foo = try signers.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }
        
    func testVerifyingEdDSAKeyUsingJWKWithMixedBase64Formats() throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using signer: JWTSigner) throws { }
        }
                
        // eddsa key in base64url format
        let x = eddsaPublicKeyBase64Url
        let d = eddsaPrivateKeyBae64

        // sign jwt
        let signer = try JWTSigner.eddsa(.private(x: x, d: d, curve: .ed25519))
        let jwt = try signer.sign(Foo(bar: 42), kid: "vapor")

        // verify using jwks without alg
        let jwksString = """
        {
            "keys": [
                {
                  "kty": "OKP",
                  "crv": "Ed25519",
                  "use": "sig",
                  "kid": "vapor",
                  "x": "\(x)",
                  "d": "\(d)"
                 }
            ]
        }
        """

        let signers = JWTSigners()
        try signers.use(jwksJSON: jwksString)
        let foo = try signers.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }

}

struct AudiencePayload: Codable {
    var audience: AudienceClaim
}

struct LocalePayload: Codable {
    var locale: LocaleClaim
}

extension LocalePayload {
    static func from(_ string: String) throws -> LocalePayload {
        let data = string.data(using: .utf8)!
        return try JSONDecoder().decode(LocalePayload.self, from: data)
    }
}

struct BoolPayload: Decodable {
    var trueStr: BoolClaim
    var trueBool: BoolClaim
    var falseStr: BoolClaim
    var falseBool: BoolClaim
}

struct BadBoolPayload: Decodable {
    var bad: BoolClaim
}

struct TestPayload: JWTPayload, Equatable {
    var sub: SubjectClaim
    var name: String
    var admin: Bool
    var exp: ExpirationClaim

    func verify(using signer: JWTSigner) throws {
        try self.exp.verifyNotExpired()
    }
}

struct ExpirationPayload: JWTPayload {
    var exp: ExpirationClaim

    func verify(using signer: JWTSigner) throws {
        try self.exp.verifyNotExpired()
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

let ecdsaPrivateKey = """
-----BEGIN PRIVATE KEY-----
MIGTAgEAMBMGByqGSM49AgEGCCqGSM49AwEHBHkwdwIBAQQg2sD+kukkA8GZUpmm
jRa4fJ9Xa/JnIG4Hpi7tNO66+OGgCgYIKoZIzj0DAQehRANCAATZp0yt0btpR9kf
ntp4oUUzTV0+eTELXxJxFvhnqmgwGAm1iVW132XLrdRG/ntlbQ1yzUuJkHtYBNve
y+77Vzsd
-----END PRIVATE KEY-----
"""
let ecdsaPublicKey = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2adMrdG7aUfZH57aeKFFM01dPnkx
C18ScRb4Z6poMBgJtYlVtd9ly63URv57ZW0Ncs1LiZB7WATb3svu+1c7HQ==
-----END PUBLIC KEY-----
"""

let rsaPrivateKey = """
-----BEGIN RSA PRIVATE KEY-----
MIICXAIBAAKBgQC0cOtPjzABybjzm3fCg1aCYwnxPmjXpbCkecAWLj/CcDWEcuTZ
kYDiSG0zgglbbbhcV0vJQDWSv60tnlA3cjSYutAv7FPo5Cq8FkvrdDzeacwRSxYu
Iq1LtYnd6I30qNaNthntjvbqyMmBulJ1mzLI+Xg/aX4rbSL49Z3dAQn8vQIDAQAB
AoGBAJeBFGLJ1EI8ENoiWIzu4A08gRWZFEi06zs+quU00f49XwIlwjdX74KP03jj
H14wIxMNjSmeixz7aboa6jmT38pQIfE3DmZoZAbKPG89SdP/S1qprQ71LgBGOuNi
LoYTZ96ZFPcHbLZVCJLPWWWX5yEqy4MS996E9gMAjSt8yNvhAkEA38MufqgrAJ0H
VSgL7ecpEhWG3PHryBfg6fK13RRpRM3jETo9wAfuPiEodnD6Qcab52H2lzMIysv1
Ex6nGv2pCQJBAM5v9SMbMG20gBzmeZvjbvxkZV2Tg9x5mWQpHkeGz8GNyoDBclAc
BFEWGKVGYV6jl+3F4nqQ6YwKBToE5KIU5xUCQEY9Im8norgCkrasZ3I6Sa4fi8H3
PqgEttk5EtVe/txWNJzHx3JsCuD9z5G+TRAwo+ex3JIBtxTRiRCDYrkaPuECQA2W
vRI0hfmSuiQs37BtRi8DBNEmFrX6oyg+tKmMrDxXcw8KrNWtInOb+r9WZK5wIl4a
epAK3fTD7Bgnnk01BwkCQHQwEdGNGN3ntYfuRzPA4KiLrt8bpACaHHr2wn9N3fRI
bxEd3Ax0uhHVqKRWNioL7UBvd4lxoReY8RmmfghZHEA=
-----END RSA PRIVATE KEY-----
"""

let rsaPublicKey = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
PmjXpbCkecAWLj/CcDWEcuTZkYDiSG0zgglbbbhcV0vJQDWSv60tnlA3cjSYutAv
7FPo5Cq8FkvrdDzeacwRSxYuIq1LtYnd6I30qNaNthntjvbqyMmBulJ1mzLI+Xg/
aX4rbSL49Z3dAQn8vQIDAQAB
-----END PUBLIC KEY-----
"""

let rsa2PrivateKey = """
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

let rsa2Cert = """
-----BEGIN CERTIFICATE-----
MIIBzjCCAXgCCQDnzO/FvcHZbjANBgkqhkiG9w0BAQsFADBuMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCTlkxDDAKBgNVBAcMA05ZQzEOMAwGA1UECgwFVmFwb3IxFDAS
BgNVBAMMC3ZhcG9yLmNvZGVzMR4wHAYJKoZIhvcNAQkBFg9qd3RAdmFwb3IuY29k
ZXMwHhcNMjAwNzMxMjMyOTQ5WhcNMjEwNzMxMjMyOTQ5WjBuMQswCQYDVQQGEwJV
UzELMAkGA1UECAwCTlkxDDAKBgNVBAcMA05ZQzEOMAwGA1UECgwFVmFwb3IxFDAS
BgNVBAMMC3ZhcG9yLmNvZGVzMR4wHAYJKoZIhvcNAQkBFg9qd3RAdmFwb3IuY29k
ZXMwXDANBgkqhkiG9w0BAQEFAANLADBIAkEAtgeOpWeiRIq0Blbcqq4P7sKnyDmj
1mpQq7OyRKZM0qbwyyMM5Nisf5Y+RSDM7JDwqMeLspGo5znLBzN5L14JIQIDAQAB
MA0GCSqGSIb3DQEBCwUAA0EAQyBP1X40S4joTg1ov4eK0aKNlRLbWftEorGh5jCc
F3IAwlztc7uFj589k/M+xO4TGdrEVlMyiVdC5/B0MLa8LQ==
-----END CERTIFICATE-----
"""

let eddsaPublicKeyBase64 = "0ZcEvMCSYqSwR8XIkxOoaYjRQSAO8frTMSCpNbUl4lE="
let eddsaPrivateKeyBae64 = "d1H3/dcg0V3XyAuZW2TE5Z3rhY20M+4YAfYu/HUQd8w="
let eddsaPublicKeyBase64Url = "0ZcEvMCSYqSwR8XIkxOoaYjRQSAO8frTMSCpNbUl4lE"
let eddsaPrivateKeyBae64Url = "d1H3_dcg0V3XyAuZW2TE5Z3rhY20M-4YAfYu_HUQd8w"

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

    func verify(using signer: JWTSigner) throws {
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

extension String {
    var bytes: [UInt8] {
        return .init(self.utf8)
    }
}
