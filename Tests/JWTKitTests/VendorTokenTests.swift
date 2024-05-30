import JWTKit
import XCTest

final class VendorTokenTests: XCTestCase {
    func testGoogleIDToken() async throws {
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

        await XCTAssertNoThrowAsync(try await collection.verify(jwt, as: GoogleIdentityToken.self))
    }

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

        await XCTAssertThrowsErrorAsync(try await collection.verify(jwt, as: GoogleIdentityToken.self)) { error in
            guard let error = error as? JWTError else {
                return XCTFail("Unexpected error: \(error)")
            }
            XCTAssertEqual(error.errorType, .claimVerificationFailure)
            XCTAssertEqual(error.reason, "Token not provided by Google")
        }
    }

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

        await XCTAssertThrowsErrorAsync(try await collection.verify(jwt, as: GoogleIdentityToken.self)) { error in
            guard let error = error as? JWTError else {
                return XCTFail("Unexpected error: \(error)")
            }
            XCTAssertEqual(error.errorType, .claimVerificationFailure)
            XCTAssertEqual(error.reason, "Subject claim beyond 255 ASCII characters long.")
        }
    }

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

        await XCTAssertNoThrowAsync(try await collection.verify(jwt, as: AppleIdentityToken.self))
    }

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

        await XCTAssertThrowsErrorAsync(try await collection.verify(jwt, as: AppleIdentityToken.self)) { error in
            guard let error = error as? JWTError else {
                return XCTFail("Unexpected error: \(error)")
            }
            XCTAssertEqual(error.errorType, .claimVerificationFailure)
            XCTAssertEqual(error.reason, "Token not provided by Apple")
        }
    }

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

        await XCTAssertNoThrowAsync(try await collection.verify(jwt, as: MicrosoftIdentityToken.self))
    }

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

        await XCTAssertThrowsErrorAsync(try await collection.verify(jwt, as: MicrosoftIdentityToken.self)) { error in
            guard let error = error as? JWTError else {
                return XCTFail("Unexpected error: \(error)")
            }
            XCTAssertEqual(error.errorType, .claimVerificationFailure)
            XCTAssertEqual(error.reason, "Token not provided by Microsoft")
        }
    }

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

        await XCTAssertThrowsErrorAsync(try await collection.verify(jwt, as: MicrosoftIdentityToken.self)) { error in
            guard let error = error as? JWTError else {
                return XCTFail("Unexpected error: \(error)")
            }
            XCTAssertEqual(error.errorType, .claimVerificationFailure)
            XCTAssertEqual(error.reason, "Token must contain tenant Id")
        }
    }
}
