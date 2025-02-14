#if canImport(Testing)
import Testing
import JWTKit

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

@Suite("VendorTokenTests")
struct VendorTokenTests {
    @Test("Test Google ID Token")
    func verifyGoogleIDToken() async throws {
        let token = GoogleIdentityToken(
            issuer: "https://accounts.google.com",
            subject: "1234567890",
            audience: "your-client-id.apps.googleusercontent.com",
            authorizedPresenter: "another-client-id.apps.googleusercontent.com",
            issuedAt: .init(value: .now),
            expires: .init(value: .now + 3600),
            atHash: "XYZ123",
            hostedDomain: "example.com",
            email: "user@example.com",
            emailVerified: true,
            name: "John Doe",
            picture: "https://example.com/johndoe.png",
            profile: "https://example.com/johndoe",
            givenName: "John",
            familyName: "Doe",
            locale: "en",
            nonce: "nonceValue"
        )

        let collection = await JWTKeyCollection().add(hmac: "secret", digestAlgorithm: .sha256)
        let jwt = try await collection.sign(token)

        await #expect(throws: Never.self) {
            try await collection.verify(jwt, as: GoogleIdentityToken.self)
        }
    }

    @Test("Test Google ID Token that is not from Google (invalid issuer)")
    func testGoogleIDTokenNotFromGoogle() async throws {
        let token = GoogleIdentityToken(
            issuer: "https://example.com",
            subject: "1234567890",
            audience: "your-client-id.apps.googleusercontent.com",
            authorizedPresenter: "another-client-id.apps.googleusercontent.com",
            issuedAt: .init(value: .now),
            expires: .init(value: .now + 3600),
            atHash: "XYZ123",
            hostedDomain: "example.com",
            email: "user@example.com",
            emailVerified: true,
            name: "John Doe",
            picture: "https://example.com/johndoe.png",
            profile: "https://example.com/johndoe",
            givenName: "John",
            familyName: "Doe",
            locale: "en",
            nonce: "nonceValue"
        )

        let collection = await JWTKeyCollection().add(hmac: "secret", digestAlgorithm: .sha256)
        let jwt = try await collection.sign(token)

        await #expect(
            throws: JWTError.claimVerificationFailure(
                failedClaim: token.issuer,
                reason: "Token not provided by Google"
            )
        ) {
            try await collection.verify(jwt, as: GoogleIdentityToken.self)
        }
    }

    @Test("Test Google ID Token with subject claim that's too big")
    func testGoogleIDTokenWithBigSubjectClaim() async throws {
        let token = GoogleIdentityToken(
            issuer: "https://accounts.google.com",
            subject: .init(stringLiteral: String(repeating: "A", count: 1000)),
            audience: "your-client-id.apps.googleusercontent.com",
            authorizedPresenter: "another-client-id.apps.googleusercontent.com",
            issuedAt: .init(value: .now),
            expires: .init(value: .now + 3600),
            atHash: "XYZ123",
            hostedDomain: "example.com",
            email: "user@example.com",
            emailVerified: true,
            name: "John Doe",
            picture: "https://example.com/johndoe.png",
            profile: "https://example.com/johndoe",
            givenName: "John",
            familyName: "Doe",
            locale: "en",
            nonce: "nonceValue"
        )

        let collection = await JWTKeyCollection().add(hmac: "secret", digestAlgorithm: .sha256)
        let jwt = try await collection.sign(token)

        await #expect(
            throws: JWTError.claimVerificationFailure(
                failedClaim: token.subject,
                reason: "Subject claim beyond 255 ASCII characters long."
            )
        ) {
            try await collection.verify(jwt, as: GoogleIdentityToken.self)
        }
    }

    @Test("Test Apple ID Token")
    func testAppleIDToken() async throws {
        let token = AppleIdentityToken(
            issuer: "https://appleid.apple.com",
            audience: "your-client-id",
            expires: .init(value: .now + 3600),
            issuedAt: .init(value: .now),
            subject: "user1234567890",
            nonceSupported: true,
            nonce: "nonce123",
            email: "user@example.com",
            orgId: "org123",
            emailVerified: true,
            isPrivateEmail: false,
            realUserStatus: .likelyReal
        )

        let collection = await JWTKeyCollection().add(hmac: "secret", digestAlgorithm: .sha256)
        let jwt = try await collection.sign(token)

        await #expect(throws: Never.self) {
            try await collection.verify(jwt, as: AppleIdentityToken.self)
        }
    }

    @Test("Test Apple ID Token that is not from Apple (invalid issuer)")
    func testAppleIDTokenNotFromApple() async throws {
        let token = AppleIdentityToken(
            issuer: "https://example.com",
            audience: "your-client-id",
            expires: .init(value: .now + 3600),
            issuedAt: .init(value: .now),
            subject: "user1234567890",
            nonceSupported: true,
            nonce: "nonce123",
            email: "user@example.com",
            orgId: "org123",
            emailVerified: true,
            isPrivateEmail: false,
            realUserStatus: .likelyReal
        )

        let collection = await JWTKeyCollection().add(hmac: "secret", digestAlgorithm: .sha256)
        let jwt = try await collection.sign(token)

        await #expect(
            throws: JWTError.claimVerificationFailure(
                failedClaim: token.issuer,
                reason: "Token not provided by Apple"
            )
        ) {
            try await collection.verify(jwt, as: AppleIdentityToken.self)
        }
    }

    @Test("Test Microsoft ID Token")
    func testMicrosoftIDToken() async throws {
        let tenantID = "some-id"

        let token = MicrosoftIdentityToken(
            audience: "your-app-client-id",
            issuer: .init(value: "https://login.microsoftonline.com/\(tenantID)/v2.0"),
            issuedAt: .init(value: .now),
            identityProvider: "https://login.microsoftonline.com/\(tenantID)/v2.0",
            notBefore: .init(value: .now),
            expires: .init(value: .now + 3600),
            codeHash: "codeHashValue",
            accessTokenHash: "accessTokenHashValue",
            preferredUsername: "user@example.com",
            email: "user@example.com",
            name: "John Doe",
            nonce: "nonceValue",
            objectId: "objectIdValue",
            roles: ["user", "admin"],
            subject: "subjectValue",
            tenantId: .init(value: tenantID),
            uniqueName: "uniqueNameValue",
            version: "2.0"
        )

        let collection = await JWTKeyCollection().add(hmac: "secret", digestAlgorithm: .sha256)
        let jwt = try await collection.sign(token)

        await #expect(throws: Never.self) {
            try await collection.verify(jwt, as: MicrosoftIdentityToken.self)
        }
    }

    @Test("Test Microsoft ID Token that is not from Microsoft (invalid issuer)")
    func testMicrosoftIDTokenNotFromMicrosoft() async throws {
        let token = MicrosoftIdentityToken(
            audience: "your-app-client-id",
            issuer: "https://example.com",
            issuedAt: .init(value: .now),
            identityProvider: "https://login.microsoftonline.com/{tenantId}/v2.0",
            notBefore: .init(value: .now),
            expires: .init(value: .now + 3600),
            codeHash: "codeHashValue",
            accessTokenHash: "accessTokenHashValue",
            preferredUsername: "user@example.com",
            email: "user@example.com",
            name: "John Doe",
            nonce: "nonceValue",
            objectId: "objectIdValue",
            roles: ["user", "admin"],
            subject: "subjectValue",
            tenantId: "tenantIdValue",
            uniqueName: "uniqueNameValue",
            version: "2.0"
        )

        let collection = await JWTKeyCollection().add(hmac: "secret", digestAlgorithm: .sha256)
        let jwt = try await collection.sign(token)

        await #expect(
            throws: JWTError.claimVerificationFailure(
                failedClaim: token.issuer,
                reason: "Token not provided by Microsoft"
            )
        ) {
            try await collection.verify(jwt, as: MicrosoftIdentityToken.self)
        }
    }

    @Test("Test Microsoft ID Token with missing tenant ID claim")
    func testMicrosoftIDTokenWithMissingTenantIDClaim() async throws {
        let token = MicrosoftIdentityToken(
            audience: "your-app-client-id",
            issuer: "https://example.com",
            issuedAt: .init(value: .now),
            identityProvider: "https://login.microsoftonline.com/{tenantId}/v2.0",
            notBefore: .init(value: .now),
            expires: .init(value: .now + 3600),
            codeHash: "codeHashValue",
            accessTokenHash: "accessTokenHashValue",
            preferredUsername: "user@example.com",
            email: "user@example.com",
            name: "John Doe",
            nonce: "nonceValue",
            objectId: "objectIdValue",
            roles: ["user", "admin"],
            subject: "subjectValue",
            tenantId: nil,
            uniqueName: "uniqueNameValue",
            version: "2.0"
        )

        let collection = await JWTKeyCollection().add(hmac: "secret", digestAlgorithm: .sha256)
        let jwt = try await collection.sign(token)

        await #expect(
            throws: JWTError.claimVerificationFailure(
                failedClaim: nil,
                reason: "Token must contain tenant Id"
            )
        ) {
            try await collection.verify(jwt, as: MicrosoftIdentityToken.self)
        }
    }

    @Test("Test Firebase ID Token")
    func testFirebaseIDToken() async throws {
        let token = FirebaseAuthIdentityToken(
            issuer: "https://securetoken.google.com/firprojectname-12345",
            subject: "1234567890",
            audience: .init(value: ["firprojectname-12345"]),
            issuedAt: .init(value: .now),
            expires: .init(value: .now + 3600),
            authTime: .now,
            userID: "1234567890",
            email: "user@example.com",
            emailVerified: true,
            phoneNumber: nil,
            name: "John Doe",
            picture: "https://example.com/johndoe.png",
            firebase: .init(
                identities: ["google.com": ["9876543210"], "email": ["user@example.com"]],
                signInProvider: "google.com"
            )
        )

        let collection = await JWTKeyCollection().add(hmac: "secret", digestAlgorithm: .sha256)
        let jwt = try await collection.sign(token)

        await #expect(throws: Never.self) {
            try await collection.verify(jwt, as: FirebaseAuthIdentityToken.self)
        }
    }

    @Test("Test Firebase ID Token that is not from Google (invalid issuer)")
    func testFirebaseIDTokenNotFromGoogle() async throws {
        let token = FirebaseAuthIdentityToken(
            issuer: "https://example.com",
            subject: "1234567890",
            audience: .init(value: ["firprojectname-12345"]),
            issuedAt: .init(value: .now),
            expires: .init(value: .now + 3600),
            authTime: .now,
            userID: "1234567890",
            email: "user@example.com",
            emailVerified: true,
            phoneNumber: nil,
            name: "John Doe",
            picture: "https://example.com/johndoe.png",
            firebase: .init(
                identities: ["google.com": ["9876543210"], "email": ["user@example.com"]],
                signInProvider: "google.com"
            )
        )

        let collection = await JWTKeyCollection().add(hmac: "secret", digestAlgorithm: .sha256)
        let jwt = try await collection.sign(token)

        await #expect(
            throws: JWTError.claimVerificationFailure(
                failedClaim: token.issuer,
                reason: "Token not provided by Google"
            )
        ) {
            try await collection.verify(jwt, as: FirebaseAuthIdentityToken.self)
        }
    }

    @Test("Test Firebase ID Token with subject claim that's too big")
    func testFirebaseIDTokenWithBigSubjectClaim() async throws {
        let token = FirebaseAuthIdentityToken(
            issuer: "https://securetoken.google.com/firprojectname-12345",
            subject: .init(stringLiteral: String(repeating: "A", count: 1000)),
            audience: .init(value: ["firprojectname-12345"]),
            issuedAt: .init(value: .now),
            expires: .init(value: .now + 3600),
            authTime: .now,
            userID: "1234567890",
            email: "user@example.com",
            emailVerified: true,
            phoneNumber: nil,
            name: "John Doe",
            picture: "https://example.com/johndoe.png",
            firebase: .init(
                identities: ["google.com": ["9876543210"], "email": ["user@example.com"]],
                signInProvider: "google.com"
            )
        )

        let collection = await JWTKeyCollection().add(hmac: "secret", digestAlgorithm: .sha256)
        let jwt = try await collection.sign(token)

        await #expect(
            throws: JWTError.claimVerificationFailure(
                failedClaim: token.subject,
                reason: "Subject claim beyond 255 ASCII characters long."
            )
        ) {
            try await collection.verify(jwt, as: FirebaseAuthIdentityToken.self)
        }
    }
}
#endif  // canImport(Testing)
