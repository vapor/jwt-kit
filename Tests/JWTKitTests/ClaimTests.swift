import JWTKit
import XCTest

final class ClaimTests: XCTestCase {
    func testBoolClaim() throws {
        let str = #"{"trueStr":"true","trueBool":true,"falseStr":"false","falseBool":false}"#
        var data = Data(str.utf8)
        let decoded = try! JSONDecoder().decode(BoolPayload.self, from: data)

        XCTAssertTrue(decoded.trueStr.value)
        XCTAssertTrue(decoded.trueBool.value)
        XCTAssertFalse(decoded.falseBool.value)
        XCTAssertFalse(decoded.falseStr.value)

        data = Data(#"{"bad":"Not boolean"}"#.utf8)
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
        let data = Data(str.utf8)
        let decoded = try! JSONDecoder().decode(AudiencePayload.self, from: data)

        XCTAssertEqual(decoded.audience.value, [id.uuidString])
        XCTAssertNoThrow(try decoded.audience.verifyIntendedAudience(includes: id.uuidString))
        XCTAssertThrowsError(try decoded.audience.verifyIntendedAudience(includes: UUID().uuidString)) {
            guard let jwtError = try? XCTUnwrap($0 as? JWTError) else { return }
            XCTAssertEqual(jwtError.errorType, .claimVerificationFailure)
            XCTAssert(jwtError.failedClaim is AudienceClaim)
            XCTAssertEqual((jwtError.failedClaim as? AudienceClaim)?.value, [id.uuidString])
        }
    }

    func testMultipleAudienceClaim() throws {
        let id1 = UUID(), id2 = UUID()
        let str = "{\"audience\":[\"\(id1.uuidString)\", \"\(id2.uuidString)\"]}"
        let data = Data(str.utf8)
        let decoded = try! JSONDecoder().decode(AudiencePayload.self, from: data)

        XCTAssertEqual(decoded.audience.value, [id1.uuidString, id2.uuidString])
        XCTAssertNoThrow(try decoded.audience.verifyIntendedAudience(includes: id1.uuidString))
        XCTAssertNoThrow(try decoded.audience.verifyIntendedAudience(includes: id2.uuidString))
        XCTAssertThrowsError(try decoded.audience.verifyIntendedAudience(includes: UUID().uuidString)) {
            guard let jwtError = try? XCTUnwrap($0 as? JWTError) else { return }
            XCTAssertEqual(jwtError.errorType, .claimVerificationFailure)
            XCTAssert(jwtError.failedClaim is AudienceClaim)
            XCTAssertEqual((jwtError.failedClaim as? AudienceClaim)?.value, [id1.uuidString, id2.uuidString])
        }
    }
    
    func testExpirationEncoding() async throws {
        let exp = ExpirationClaim(value: Date(timeIntervalSince1970: 2_000_000_000))
        let parser = DefaultJWTParser()
        let keyCollection = await JWTKeyCollection().addHS256(key: "secret".bytes, parser: parser)
        let jwt = try await keyCollection.sign(ExpirationPayload(exp: exp))
        let parsed = try parser.parse(jwt.bytes, as: ExpirationPayload.self)
        let header = parsed.header
        let typ = try XCTUnwrap(header.typ)
        XCTAssertEqual(typ, "JWT")
        let alg = try XCTUnwrap(header.alg)
        XCTAssertEqual(alg, "HS256")
        XCTAssertEqual(parsed.payload.exp, exp)
        _ = try await keyCollection.verify(jwt, as: ExpirationPayload.self)
    }
}
