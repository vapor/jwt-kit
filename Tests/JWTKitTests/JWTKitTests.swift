import XCTest
@testable import JWTKit

class JWTKitTests: XCTestCase {
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
        var parser = try JWTParser(token: jwt.bytes)
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

        let privateSigner = try JWTSigner.jwk(json: privateKey)
        let publicSigner = try JWTSigner.jwk(json: publicKey)

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let data = try privateSigner.sign(payload)
        // test private signer decoding
        try XCTAssertEqual(privateSigner.verify(data, as: TestPayload.self), payload)
        // test public signer decoding
        try XCTAssertEqual(publicSigner.verify(data, as: TestPayload.self), payload)
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

extension String {
    var bytes: [UInt8] {
        return .init(self.utf8)
    }
}
