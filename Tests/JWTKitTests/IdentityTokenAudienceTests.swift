import CryptoExtras
import JWTKit
import Testing

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

@Suite("Identity token audience binding")
struct IdentityTokenAudienceTests {
    private func expectJWTError<Value>(
        _ errorType: JWTError.ErrorType,
        reason: String,
        performing body: () async throws -> Value
    ) async {
        do {
            _ = try await body()
            Issue.record("Expected JWTError with reason: \(reason)")
        } catch let error as JWTError {
            #expect(error.errorType == errorType)
            #expect(error.reason == reason)
        } catch {
            Issue.record("Expected JWTError, got \(error)")
        }
    }

    enum Provider: String, CaseIterable, Sendable {
        case apple, google, microsoft, firebase

        func issuer(for audience: String) -> String {
            switch self {
            case .apple: "https://appleid.apple.com"
            case .google: "https://accounts.google.com"
            case .microsoft: "https://login.microsoftonline.com/11111111-2222-3333-4444-555555555555/v2.0"
            case .firebase: "https://securetoken.google.com/\(audience)"
            }
        }

        func verify(
            _ token: String,
            using keys: JWTKeyCollection,
            expectedAudience: String,
            trustedAdditionalAudiences: Set<String> = [],
            trustedAuthorizedPresenters: Set<String>? = nil,
            bytes: Bool = false
        ) async throws -> AudienceClaim {
            switch self {
            case .apple:
                let payload: AppleIdentityToken
                if bytes {
                    payload = try await keys.verify(
                        Array(token.utf8), as: AppleIdentityToken.self,
                        expectedAudience: expectedAudience,
                        trustedAdditionalAudiences: trustedAdditionalAudiences)
                } else {
                    payload = try await keys.verify(
                        token, as: AppleIdentityToken.self,
                        expectedAudience: expectedAudience,
                        trustedAdditionalAudiences: trustedAdditionalAudiences)
                }
                return payload.audience
            case .google:
                let payload: GoogleIdentityToken
                if bytes {
                    if let trustedAuthorizedPresenters {
                        payload = try await keys.verify(
                            Array(token.utf8), as: GoogleIdentityToken.self,
                            expectedAudience: expectedAudience,
                            trustedAdditionalAudiences: trustedAdditionalAudiences,
                            trustedAuthorizedPresenters: trustedAuthorizedPresenters)
                    } else {
                        payload = try await keys.verify(
                            Array(token.utf8), as: GoogleIdentityToken.self,
                            expectedAudience: expectedAudience,
                            trustedAdditionalAudiences: trustedAdditionalAudiences)
                    }
                } else {
                    if let trustedAuthorizedPresenters {
                        payload = try await keys.verify(
                            token, as: GoogleIdentityToken.self,
                            expectedAudience: expectedAudience,
                            trustedAdditionalAudiences: trustedAdditionalAudiences,
                            trustedAuthorizedPresenters: trustedAuthorizedPresenters)
                    } else {
                        payload = try await keys.verify(
                            token, as: GoogleIdentityToken.self,
                            expectedAudience: expectedAudience,
                            trustedAdditionalAudiences: trustedAdditionalAudiences)
                    }
                }
                return payload.audience
            case .microsoft:
                let payload: MicrosoftIdentityToken
                if bytes {
                    payload = try await keys.verify(
                        Array(token.utf8), as: MicrosoftIdentityToken.self,
                        expectedAudience: expectedAudience,
                        trustedAdditionalAudiences: trustedAdditionalAudiences)
                } else {
                    payload = try await keys.verify(
                        token, as: MicrosoftIdentityToken.self,
                        expectedAudience: expectedAudience,
                        trustedAdditionalAudiences: trustedAdditionalAudiences)
                }
                return payload.audience
            case .firebase:
                let payload: FirebaseAuthIdentityToken
                if bytes {
                    payload = try await keys.verify(
                        Array(token.utf8), as: FirebaseAuthIdentityToken.self,
                        expectedAudience: expectedAudience,
                        trustedAdditionalAudiences: trustedAdditionalAudiences)
                } else {
                    payload = try await keys.verify(
                        token, as: FirebaseAuthIdentityToken.self,
                        expectedAudience: expectedAudience,
                        trustedAdditionalAudiences: trustedAdditionalAudiences)
                }
                return payload.audience
            }
        }

        func verify(
            _ token: String,
            using keys: JWTKeyCollection,
            expectedAudiences: Set<String>,
            trustedAdditionalAudiences: Set<String> = [],
            trustedAuthorizedPresenters: Set<String>? = nil,
            bytes: Bool = false
        ) async throws -> AudienceClaim {
            func verifyPayload<P: JWTIdentityToken>(_ type: P.Type) async throws -> AudienceClaim {
                let payload: P
                if bytes {
                    payload = try await keys.verify(
                        Array(token.utf8), as: type,
                        expectedAudiences: expectedAudiences,
                        trustedAdditionalAudiences: trustedAdditionalAudiences)
                } else {
                    payload = try await keys.verify(
                        token, as: type,
                        expectedAudiences: expectedAudiences,
                        trustedAdditionalAudiences: trustedAdditionalAudiences)
                }
                return payload.audience
            }

            switch self {
            case .apple: return try await verifyPayload(AppleIdentityToken.self)
            case .google:
                if let trustedAuthorizedPresenters {
                    let payload: GoogleIdentityToken
                    if bytes {
                        payload = try await keys.verify(
                            Array(token.utf8), as: GoogleIdentityToken.self,
                            expectedAudiences: expectedAudiences,
                            trustedAdditionalAudiences: trustedAdditionalAudiences,
                            trustedAuthorizedPresenters: trustedAuthorizedPresenters)
                    } else {
                        payload = try await keys.verify(
                            token, as: GoogleIdentityToken.self,
                            expectedAudiences: expectedAudiences,
                            trustedAdditionalAudiences: trustedAdditionalAudiences,
                            trustedAuthorizedPresenters: trustedAuthorizedPresenters)
                    }
                    return payload.audience
                }
                return try await verifyPayload(GoogleIdentityToken.self)
            case .microsoft: return try await verifyPayload(MicrosoftIdentityToken.self)
            case .firebase: return try await verifyPayload(FirebaseAuthIdentityToken.self)
            }
        }

        // The generic shape also tests callers whose payload type is abstracted
        // behind JWTPayload and therefore cannot see the deprecation warning.
        func verifyWithoutAudience(_ token: String, using keys: JWTKeyCollection) async throws {
            func verify<P: JWTPayload>(_ type: P.Type) async throws {
                let _: P = try await keys.verify(token, as: type)
            }
            switch self {
            case .apple: try await verify(AppleIdentityToken.self)
            case .google: try await verify(GoogleIdentityToken.self)
            case .microsoft: try await verify(MicrosoftIdentityToken.self)
            case .firebase: try await verify(FirebaseAuthIdentityToken.self)
            }
        }
    }

    // Signing this fixture exercises the actual provider decoders and verifiers
    // without requiring live provider accounts or keys.
    struct Fixture: JWTPayload {
        enum CodingKeys: String, CodingKey {
            case iss, aud, sub, azp, iat, exp, nbf, tid, oid, ver
            case userID = "user_id"
        }

        var iss: String
        var aud: AudienceClaim
        var sub = "local-test-subject"
        var azp: String
        var iat = Int(Date().timeIntervalSince1970)
        var exp = Int(Date().addingTimeInterval(3600).timeIntervalSince1970)
        var nbf = Int(Date().addingTimeInterval(-60).timeIntervalSince1970)
        var tid = "11111111-2222-3333-4444-555555555555"
        var oid = "local-test-object"
        var ver = "2.0"
        var userID = "local-test-subject"

        func verify(using _: some JWTAlgorithm) async throws {}
    }

    @Test(arguments: ["HS256", "RS256"], Provider.allCases)
    func bindsAudience(algorithm: String, provider: Provider) async throws {
        let signing = JWTKeyCollection()
        let verifying = JWTKeyCollection()
        if algorithm == "HS256" {
            await signing.add(hmac: "local-test-key-with-at-least-32-bytes", digestAlgorithm: .sha256)
            await verifying.add(hmac: "local-test-key-with-at-least-32-bytes", digestAlgorithm: .sha256)
        } else {
            let key = try Insecure.RSA.PrivateKey(backing: .init(keySize: .bits2048))
            await signing.add(rsa: key, digestAlgorithm: .sha256)
            await verifying.add(rsa: key.publicKey, digestAlgorithm: .sha256)
        }

        let wrong = Fixture(iss: provider.issuer(for: "other-client"), aud: "other-client", azp: "our-client")
        let wrongJWT = try await signing.sign(wrong)
        await self.expectJWTError(.claimVerificationFailure, reason: "Token was not issued for an expected audience") {
            try await provider.verify(wrongJWT, using: verifying, expectedAudience: "our-client")
        }

        var matching = wrong
        matching.iss = provider.issuer(for: "our-client")
        matching.aud = "our-client"
        matching.azp = "our-client"
        let matchingJWT = try await signing.sign(matching)
        for bytes in [false, true] {
            let audience = try await provider.verify(
                matchingJWT, using: verifying, expectedAudience: "our-client", bytes: bytes)
            #expect(audience.value == ["our-client"])
        }

        // The deprecated call must keep working for vapor/jwt until its next release.
        // A caller using it still has to check the returned audience itself.
        try await provider.verifyWithoutAudience(wrongJWT, using: verifying)
        await self.expectJWTError(.generic, reason: "Expected audience must not be empty") {
            try await provider.verify(matchingJWT, using: verifying, expectedAudience: "")
        }

        var multi = matching
        multi.aud = .init(value: ["our-client", "other-client"])
        let multiJWT = try await signing.sign(multi)
        await self.expectJWTError(.claimVerificationFailure, reason: "Token includes an untrusted audience") {
            try await provider.verify(multiJWT, using: verifying, expectedAudience: "our-client")
        }
        let trustedAudience = try await provider.verify(
            multiJWT, using: verifying, expectedAudience: "our-client",
            trustedAdditionalAudiences: ["other-client"])
        #expect(trustedAudience.value == ["our-client", "other-client"])

        if provider == .google {
            var wrongPresenter = matching
            wrongPresenter.azp = "other-client"
            let presenterJWT = try await signing.sign(wrongPresenter)
            for bytes in [false, true] {
                // A mobile client can present a token for the backend client ID.
                _ = try await provider.verify(
                    presenterJWT, using: verifying, expectedAudience: "our-client", bytes: bytes)
                await self.expectJWTError(.claimVerificationFailure, reason: "Google identity token has an untrusted authorized presenter")
                {
                    try await provider.verify(
                        presenterJWT, using: verifying, expectedAudience: "our-client",
                        trustedAuthorizedPresenters: [], bytes: bytes)
                }
                _ = try await provider.verify(
                    presenterJWT, using: verifying, expectedAudience: "our-client",
                    trustedAuthorizedPresenters: ["other-client"], bytes: bytes)
            }
        }
    }

    @Test(arguments: Provider.allCases)
    func acceptsMultipleConfiguredClients(provider: Provider) async throws {
        let keys = await JWTKeyCollection().add(
            hmac: "local-test-key-with-at-least-32-bytes", digestAlgorithm: .sha256)
        let expectedAudiences: Set<String> = ["web-client", "mobile-client"]
        let clientIDs = ["web-client", "mobile-client"]

        for clientID in expectedAudiences {
            let fixture = Fixture(iss: provider.issuer(for: clientID), aud: .init(value: [clientID]), azp: clientID)
            let token = try await keys.sign(fixture)
            if provider == .apple {
                let verified = try await keys.verify(
                    token, as: AppleIdentityToken.self, expectedAudiences: clientIDs)
                #expect(verified.audience.value == [clientID])
            }
            if provider == .google {
                let verified = try await keys.verify(
                    token, as: GoogleIdentityToken.self, expectedAudiences: clientIDs,
                    trustedAuthorizedPresenters: [])
                #expect(verified.audience.value == [clientID])
            }
            for bytes in [false, true] {
                let audience = try await provider.verify(
                    token, using: keys, expectedAudiences: expectedAudiences, bytes: bytes)
                #expect(audience.value == [clientID])
            }

            await self.expectJWTError(.generic, reason: "Expected audience must not be empty") {
                try await provider.verify(token, using: keys, expectedAudiences: [])
            }
            await self.expectJWTError(.generic, reason: "Expected audience must not be empty") {
                try await provider.verify(token, using: keys, expectedAudiences: ["", clientID])
            }
        }

        let other = Fixture(iss: provider.issuer(for: "other-client"), aud: "other-client", azp: "other-client")
        let otherToken = try await keys.sign(other)
        await self.expectJWTError(.claimVerificationFailure, reason: "Token was not issued for an expected audience") {
            try await provider.verify(
                otherToken, using: keys, expectedAudiences: expectedAudiences,
                trustedAdditionalAudiences: ["other-client"])
        }

        var both = Fixture(iss: provider.issuer(for: "web-client"), aud: "web-client", azp: "mobile-client")
        both.aud = .init(value: ["web-client", "mobile-client"])
        let bothToken = try await keys.sign(both)
        let bothAudience = try await provider.verify(
            bothToken, using: keys, expectedAudiences: expectedAudiences)
        #expect(bothAudience.value == ["web-client", "mobile-client"])

        var mixed = both
        mixed.aud = .init(value: ["web-client", "other-client"])
        let mixedToken = try await keys.sign(mixed)
        await self.expectJWTError(.claimVerificationFailure, reason: "Token includes an untrusted audience") {
            try await provider.verify(mixedToken, using: keys, expectedAudiences: expectedAudiences)
        }
        let trustedAudience = try await provider.verify(
            mixedToken, using: keys, expectedAudiences: expectedAudiences,
            trustedAdditionalAudiences: ["other-client"])
        #expect(trustedAudience.value == ["web-client", "other-client"])

        if provider == .google {
            var wrongPresenter = both
            wrongPresenter.azp = "other-client"
            let presenterToken = try await keys.sign(wrongPresenter)
            _ = try await provider.verify(
                presenterToken, using: keys, expectedAudiences: expectedAudiences)
            await self.expectJWTError(.claimVerificationFailure, reason: "Google identity token has an untrusted authorized presenter") {
                try await provider.verify(
                    presenterToken, using: keys, expectedAudiences: expectedAudiences,
                    trustedAuthorizedPresenters: [])
            }
            _ = try await provider.verify(
                presenterToken, using: keys, expectedAudiences: expectedAudiences,
                trustedAuthorizedPresenters: ["other-client"])
        }
    }

    @Test("Audience validation also applies to JWKS verification")
    func validatesWithJWKS() async throws {
        let key = try Insecure.RSA.PrivateKey(
            modulus: rsaModulus, exponent: publicExponent, privateExponent: rsaPrivateExponent)
        let signing = await JWTKeyCollection().add(rsa: key, digestAlgorithm: .sha256, kid: "provider")
        let jwks = """
            {"keys":[{"kty":"RSA","alg":"RS256","kid":"provider","n":"\(rsaModulus)","e":"\(publicExponent)"}]}
            """
        let verifying = try await JWTKeyCollection().add(jwksJSON: jwks)
        let fixture = Fixture(iss: Provider.apple.issuer(for: "other-client"), aud: "other-client", azp: "other-client")
        let token = try await signing.sign(fixture, kid: "provider")

        await self.expectJWTError(.claimVerificationFailure, reason: "Token was not issued for an expected audience") {
            try await verifying.verify(token, as: AppleIdentityToken.self, expectedAudience: "our-client")
        }
        let accepted = try await verifying.verify(
            token, as: AppleIdentityToken.self, expectedAudience: "other-client")
        #expect(accepted.audience.value == ["other-client"])
    }
}
