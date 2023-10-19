@testable import JWTKit
import XCTest

final class ClaimTests: XCTestCase {
    func testClaimDocs() throws {
        struct TestPayload: JWTPayload {
            enum CodingKeys: String, CodingKey {
                case audience = "aud"
            }

            var audience: AudienceClaim

            func verify(using _: JWTSigner) throws {
                try audience.verifyIntendedAudience(includes: "foo")
            }
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
