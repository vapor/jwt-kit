#if canImport(Testing)
import Testing
import JWTKit

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

@Suite("Claim Tests")
struct ClaimTests {
    @Test("Test Claim with Boolean")
    func boolClaim() async throws {
        let payload = #"{"trueStr":"true","trueBool":true,"falseStr":"false","falseBool":false}"#
        var data = Data(payload.utf8)
        let decoded = try! JSONDecoder().decode(BoolPayload.self, from: data)

        #expect(decoded.trueStr.value == true)
        #expect(decoded.trueBool.value == true)
        #expect(decoded.falseBool.value == false)
        #expect(decoded.falseStr.value == false)

        data = Data(#"{"bad":"Not boolean"}"#.utf8)
        #expect(throws: DecodingError.self) {
            try JSONDecoder().decode(BoolPayload.self, from: data)
        }
    }

    @Test("Test Claim with Locale")
    func localeClaim() async throws {
        let ptBR = #"{"locale":"pt-BR"}"#

        let plainEnglish = try LocalePayload.from(#"{"locale":"en"}"#)
        let brazillianPortugese = try LocalePayload.from(ptBR)
        let nadizaDialectSlovenia = try LocalePayload.from(#"{"locale":"sl-nedis"}"#)
        let germanSwissPost1996 = try LocalePayload.from(#"{"locale":"de-CH-1996"}"#)
        let chineseTraditionalTwoPrivate = try LocalePayload.from(
            #"{"locale":"zh-Hant-CN-x-private1-private2"}"#
        )

        #expect(plainEnglish.locale.value.identifier == "en")
        #expect(brazillianPortugese.locale.value.identifier == "pt-BR")
        #expect(nadizaDialectSlovenia.locale.value.identifier == "sl-nedis")
        #expect(germanSwissPost1996.locale.value.identifier == "de-CH-1996")
        #expect(chineseTraditionalTwoPrivate.locale.value.identifier == "zh-Hant-CN-x-private1-private2")

        let encoded = try JSONEncoder().encode(brazillianPortugese)
        let string = String(bytes: encoded, encoding: .utf8)!
        #expect(string == ptBR)
    }

    @Test("Test Claim with Sindle Audience")
    func singleAudienceClaim() async throws {
        let id = UUID()
        let str = "{\"audience\":\"\(id.uuidString)\"}"
        let data = Data(str.utf8)
        let decoded = try! JSONDecoder().decode(AudiencePayload.self, from: data)

        #expect(decoded.audience.value == [id.uuidString])
        #expect(throws: Never.self) {
            try decoded.audience.verifyIntendedAudience(includes: id.uuidString)
        }
        #expect {
            try decoded.audience.verifyIntendedAudience(includes: UUID().uuidString)
        } throws: { error in
            guard let jwtError = error as? JWTError else { return false }
            return jwtError.errorType == .claimVerificationFailure
                && jwtError.failedClaim is AudienceClaim
                && (jwtError.failedClaim as? AudienceClaim)?.value == [id.uuidString]
        }
    }

    @Test("Test Claim with Multiple Audiences")
    func multipleAudienceClaims() async throws {
        let id1 = UUID()
        let id2 = UUID()
        let str = "{\"audience\":[\"\(id1.uuidString)\", \"\(id2.uuidString)\"]}"
        let data = Data(str.utf8)
        let decoded = try! JSONDecoder().decode(AudiencePayload.self, from: data)

        #expect(decoded.audience.value == [id1.uuidString, id2.uuidString])
        #expect(throws: Never.self) {
            try decoded.audience.verifyIntendedAudience(includes: id1.uuidString)
        }
        #expect(throws: Never.self) {
            try decoded.audience.verifyIntendedAudience(includes: id2.uuidString)
        }
        #expect {
            try decoded.audience.verifyIntendedAudience(includes: UUID().uuidString)
        } throws: { error in
            guard let jwtError = error as? JWTError else { return false }
            return jwtError.errorType == .claimVerificationFailure
                && jwtError.failedClaim is AudienceClaim
                && (jwtError.failedClaim as? AudienceClaim)?.value == [
                    id1.uuidString, id2.uuidString,
                ]
        }
    }

    @Test("Test Expiration Encoding")
    func expirationEncoding() async throws {
        let exp = ExpirationClaim(value: Date(timeIntervalSince1970: 2_000_000_000))
        let parser = DefaultJWTParser()
        let keyCollection = await JWTKeyCollection()
            .add(hmac: .init(from: "secret".bytes), digestAlgorithm: .sha256, parser: parser)
        let jwt = try await keyCollection.sign(ExpirationPayload(exp: exp))
        let parsed = try parser.parse(jwt.bytes, as: ExpirationPayload.self)
        let header = parsed.header

        let typ = try #require(header.typ)
        #expect(typ == "JWT")
        let alg = try #require(header.alg)
        #expect(alg == "HS256")
        #expect(parsed.payload.exp == exp)
        _ = try await keyCollection.verify(jwt, as: ExpirationPayload.self)
    }
}
#endif  // canImport(Testing)
