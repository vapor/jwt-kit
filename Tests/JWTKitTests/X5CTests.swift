#if canImport(Testing)
import Testing
import JWTKit
@_spi(FixedExpiryValidationTime) import X509

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

/// Test the x5c verification abilities of JWTSigners.
///
/// In these tests, there are 4 certificates:
/// - Root
/// - Intermediate
/// - Leaf
/// - Leaf expired
///
/// All tokens in these tests have been signed with the "Leaf" private key.
/// "Root" is the trusted, self-signed certificate. "Intermediate" is signed by
/// "Root" and "Leaf" is signed by "Intermediate."
///
/// "Leaf expired" has the same private key as "Leaf" but is meant to expire Oct 30 16:06:22 2022 GMT.
///
/// Only tokens with an x5c chain that starts with "Leaf"
/// and ends in either "Intermediate" or "Root" should
/// successfully be verified.
///
/// Note: if the certificates are expired and need updating, see the `scripts/generateTokens.swift` file.
@Suite("X5CTests")
struct X5CTests {
    let verifier = try! X5CVerifier(rootCertificates: [
        // Trusted root:
        """
        -----BEGIN CERTIFICATE-----
        MIICiTCCAi+gAwIBAgIUAQnnizzn/hIrJBy3tPG/BsT8zdwwCgYIKoZIzj0EAwIw
        gZkxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhOZXcgWW9yazERMA8GA1UEBwwITmV3
        IFlvcmsxDjAMBgNVBAoMBVZhcG9yMRQwEgYDVQQLDAtFbmdpbmVlcmluZzEWMBQG
        A1UEAwwNVmFwb3IgUm9vdCBDQTEmMCQGCSqGSIb3DQEJARYXYWRtaW5AdmFwb3Iu
        ZXhhbXBsZS5jb20wHhcNMjYwMjA5MTIxNTE2WhcNMzYwMjA3MTIxNTE2WjCBmTEL
        MAkGA1UEBhMCVVMxETAPBgNVBAgMCE5ldyBZb3JrMREwDwYDVQQHDAhOZXcgWW9y
        azEOMAwGA1UECgwFVmFwb3IxFDASBgNVBAsMC0VuZ2luZWVyaW5nMRYwFAYDVQQD
        DA1WYXBvciBSb290IENBMSYwJAYJKoZIhvcNAQkBFhdhZG1pbkB2YXBvci5leGFt
        cGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAtmAodPfalJ6lBwjOtw
        UW/n0c92tBWDtOdb+SgHUHKbq5vXrlmDwkcje44fXgUbH0fc/WtL/6w5pq55UbzN
        C2ejUzBRMB0GA1UdDgQWBBR5J5DrZfuJ1v6ZwsXcbSuAFDKx+jAfBgNVHSMEGDAW
        gBR5J5DrZfuJ1v6ZwsXcbSuAFDKx+jAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49
        BAMCA0gAMEUCIQDtFydbBhYIx3Y1cTo3OjzZZvsEjZQa/1yHGyk/uA/j/wIgMeJS
        NxQDLTGLvHoYZxtqO4i2kc+Z3KedZ0ki+Zi4Fk0=
        -----END CERTIFICATE-----
        """
    ])

    func check(
        token: String
    ) async throws {
        _ = try await verifier.verifyJWS(
            token,
            as: TokenPayload.self
        )
    }

    /// x5c: [leaf, intermediate, root]
    ///
    /// Should pass validation.
    @Test("Test valid certificate chain")
    func verifyValidChain() async throws {
        await #expect(throws: Never.self, "Valid certificate chain was not verified.") {
            try await check(token: validToken)
        }
    }

    /// x5c: [leaf, root]
    ///
    /// Should fail validation.
    @Test("Test missing intermediate certificate")
    func verifyMissingIntermediate() async throws {
        await #expect(throws: (any Error).self, "Missing intermediate cert should throw an error.") {
            try await check(token: missingIntermediateToken)
        }
    }

    /// x5c: [leaf, intermediate]
    ///
    /// Should pass validation.
    ///
    /// RFC 5280, section 6 (https://datatracker.ietf.org/doc/html/rfc5280#section-6.1)
    /// says:
    /// > When the trust anchor is provided in the form of a self-signed
    /// > certificate, this self-signed certificate is not included as part of
    /// > the prospective certification path.
    ///
    /// Some providers do include the root certificate as
    /// the final element in the chain, but the above RFC
    /// seems to say it's not necessary.
    @Test("Test missing root certificate")
    func verifyMissingRoot() async throws {
        await #expect(throws: Never.self, "Missing root cert should not throw an error.") {
            try await check(token: missingRootToken)
        }
    }

    /// x5c: [intermediate, root]
    ///
    /// Should fail validation.
    @Test("Test missing leaf certificate")
    func verifyMissingLeaf() async throws {
        await #expect(throws: (any Error).self, "Missing leaf cert should throw an error.") {
            try await check(token: missingLeafToken)
        }
    }

    /// x5c: [root]
    ///
    /// Should fail validation.
    @Test("Test missing leaf and intermediate certificates")
    func verifyMissingLeafAndIntermediate() async throws {
        await #expect(throws: (any Error).self, "Missing leaf/intermediate cert should throw an error.") {
            try await check(token: missingLeafAndIntermediateToken)
        }
    }

    /// x5c: [leaf]
    ///
    /// Should fail validation.
    @Test("Test missing intermediate and root certificates")
    func verifyMissingIntermediateAndRoot() async throws {
        await #expect(throws: (any Error).self, "Missing intermediate/root cert should throw an error.") {
            try await check(token: missingIntermediateAndRootToken)
        }
    }

    /// x5c: [expired_leaf, intermediate, root]
    ///
    /// Should fail validation because leaf is epxired.
    @Test("Test expired leaf certificate")
    func verifyExpiredLeaf() async throws {
        await #expect(throws: (any Error).self, "Expired leaf cert should throw an error.") {
            try await check(token: expiredLeafToken)
        }
    }

    /// x5c: [leaf, intermediate, root]
    ///
    /// Should fail validation because it's not cool!
    ///
    /// This is a test to make sure that the claims actually
    /// get verified.
    @Test("Test valid but not cool")
    func verifyValidButNotCool() async throws {
        await #expect(throws: (any Error).self, "Token isn't cool. Claims weren't verified.") {
            try await check(token: validButNotCoolToken)
        }
    }

    @Test("Test App Store JWT")
    func verifyAppStoreJWT() async throws {
        let cert = """
            -----BEGIN CERTIFICATE-----
            MIIBXDCCAQICCQCfjTUGLDnR9jAKBggqhkjOPQQDAzA2MQswCQYDVQQGEwJVUzET
            MBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJQ3VwZXJ0aW5vMB4XDTIzMDEw
            NDE2MjAzMloXDTMzMDEwMTE2MjAzMlowNjELMAkGA1UEBhMCVVMxEzARBgNVBAgM
            CkNhbGlmb3JuaWExEjAQBgNVBAcMCUN1cGVydGlubzBZMBMGByqGSM49AgEGCCqG
            SM49AwEHA0IABHPvwZfoKLKaOrX/We4qObXSna5TdWHVZ6hIRA1w0oc3QCT0Io2p
            lyDB3/MVlk2tc4KGE8TiqW7ibQ6Zc9V64k0wCgYIKoZIzj0EAwMDSAAwRQIhAMTH
            hWtbAQN0hSxIXcP4CKrDCH/gsxWpx6jTZLTeZ+FPAiB35nwk5q0zcIpefvYJ0MU/
            yGGHSWez0bq0pDYUO/nmDw==
            -----END CERTIFICATE-----
            """

        // https://github.com/apple/app-store-server-library-swift/blob/main/Tests/AppStoreServerLibraryTests/SignedDataVerifierTests.swift#L98
        let token = """
            eyJ4NWMiOlsiTUlJQm9EQ0NBVWFnQXdJQkFnSUJDekFLQmdncWhrak9QUVFEQWpCTk1Rc3dDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVDQXdLUTJGc2FXWnZjbTVwWVRFU01CQUdBMVVFQnd3SlEzVndaWEowYVc1dk1SVXdFd1lEVlFRS0RBeEpiblJsY20xbFpHbGhkR1V3SGhjTk1qTXdNVEEwTVRZek56TXhXaGNOTXpJeE1qTXhNVFl6TnpNeFdqQkZNUXN3Q1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0F3S1EyRnNhV1p2Y201cFlURVNNQkFHQTFVRUJ3d0pRM1Z3WlhKMGFXNXZNUTB3Q3dZRFZRUUtEQVJNWldGbU1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRTRyV0J4R21GYm5QSVBRSTB6c0JLekx4c2o4cEQydnFicjB5UElTVXgyV1F5eG1yTnFsOWZoSzhZRUV5WUZWNysrcDVpNFlVU1Ivbzl1UUlnQ1BJaHJLTWZNQjB3Q1FZRFZSMFRCQUl3QURBUUJnb3Foa2lHOTJOa0Jnc0JCQUlUQURBS0JnZ3Foa2pPUFFRREFnTklBREJGQWlFQWtpRVprb0ZNa2o0Z1huK1E5alhRWk1qWjJnbmpaM2FNOE5ZcmdmVFVpdlFDSURKWVowRmFMZTduU0lVMkxXTFRrNXRYVENjNEU4R0pTWWYvc1lSeEVGaWUiLCJNSUlCbHpDQ0FUMmdBd0lCQWdJQkJqQUtCZ2dxaGtqT1BRUURBakEyTVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNBd0tRMkZzYVdadmNtNXBZVEVTTUJBR0ExVUVCd3dKUTNWd1pYSjBhVzV2TUI0WERUSXpNREV3TkRFMk1qWXdNVm9YRFRNeU1USXpNVEUyTWpZd01Wb3dUVEVMTUFrR0ExVUVCaE1DVlZNeEV6QVJCZ05WQkFnTUNrTmhiR2xtYjNKdWFXRXhFakFRQmdOVkJBY01DVU4xY0dWeWRHbHViekVWTUJNR0ExVUVDZ3dNU1c1MFpYSnRaV1JwWVhSbE1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUZRM2xYMnNxTjlHSXdBaWlNUURRQy9reW5TZ1g0N1J3dmlET3RNWFh2eUtkUWU2Q1BzUzNqbzJ1UkR1RXFBeFdlT2lDcmpsRFdzeXo1d3dkVTBndGFxTWxNQ013RHdZRFZSMFRCQWd3QmdFQi93SUJBREFRQmdvcWhraUc5Mk5rQmdJQkJBSVRBREFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUVBdm56TWNWMjY4Y1JiMS9GcHlWMUVoVDNXRnZPenJCVVdQNi9Ub1RoRmF2TUNJRmJhNXQ2WUt5MFIySkR0eHF0T2pKeTY2bDZWN2QvUHJBRE5wa21JUFcraSIsIk1JSUJYRENDQVFJQ0NRQ2ZqVFVHTERuUjlqQUtCZ2dxaGtqT1BRUURBekEyTVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNBd0tRMkZzYVdadmNtNXBZVEVTTUJBR0ExVUVCd3dKUTNWd1pYSjBhVzV2TUI0WERUSXpNREV3TkRFMk1qQXpNbG9YRFRNek1ERXdNVEUyTWpBek1sb3dOakVMTUFrR0ExVUVCaE1DVlZNeEV6QVJCZ05WQkFnTUNrTmhiR2xtYjNKdWFXRXhFakFRQmdOVkJBY01DVU4xY0dWeWRHbHViekJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCSFB2d1pmb0tMS2FPclgvV2U0cU9iWFNuYTVUZFdIVlo2aElSQTF3MG9jM1FDVDBJbzJwbHlEQjMvTVZsazJ0YzRLR0U4VGlxVzdpYlE2WmM5VjY0azB3Q2dZSUtvWkl6ajBFQXdNRFNBQXdSUUloQU1USGhXdGJBUU4waFN4SVhjUDRDS3JEQ0gvZ3N4V3B4NmpUWkxUZVorRlBBaUIzNW53azVxMHpjSXBlZnZZSjBNVS95R0dIU1dlejBicTBwRFlVTy9ubUR3PT0iXSwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTYifQ.eyJkYXRhIjp7ImFwcEFwcGxlSWQiOjEyMzQsImVudmlyb25tZW50IjoiU2FuZGJveCIsImJ1bmRsZUlkIjoiY29tLmV4YW1wbGUifSwibm90aWZpY2F0aW9uVVVJRCI6IjlhZDU2YmQyLTBiYzYtNDJlMC1hZjI0LWZkOTk2ZDg3YTFlNiIsInNpZ25lZERhdGUiOjE2ODEzMTQzMjQwMDAsIm5vdGlmaWNhdGlvblR5cGUiOiJURVNUIn0.VVXYwuNm2Y3XsOUva-BozqatRCsDuykA7xIe_CCRw6aIAAxJ1nb2sw871jfZ6dcgNhUuhoZ93hfbc1v_5zB7Og
            """

        struct StoreKitPayload: ValidationTimePayload {
            struct DataClass: Codable {
                let appAppleId: Int
                let environment, bundleId: String
            }

            let data: DataClass
            let notificationUUID: String
            let signedDate: Date
            let notificationType: String

            func verify(using _: some JWTAlgorithm) async throws {}
        }

        let verifier = try X5CVerifier(rootCertificates: [cert])

        let jsonDecoder = JSONDecoder()
        jsonDecoder.dateDecodingStrategy = .millisecondsSince1970

        var payload: StoreKitPayload?
        do {
            payload = try await verifier.verifyJWS(token, as: StoreKitPayload.self, jsonDecoder: jsonDecoder)
        } catch {
            Issue.record("Failed with error: \(error.localizedDescription)")
        }

        let data = try #require(payload).data
        #expect(data.appAppleId == 1234)
        #expect(data.environment == "Sandbox")
    }

    @Test("Test init from DER")
    func initFromDER() async throws {
        let derCertificate: [UInt8] = [
            0x30, 0x82, 0x01, 0x82, 0x30, 0x82, 0x01, 0x29, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x09, 0x00,
            0xB5, 0x1C, 0xE4, 0x02, 0xE2, 0x1F, 0x9A, 0x5B, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE,
            0x3D, 0x04, 0x03, 0x03, 0x30, 0x36, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13,
            0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06, 0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x43, 0x61,
            0x6C, 0x69, 0x66, 0x6F, 0x72, 0x6E, 0x69, 0x61, 0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04,
            0x07, 0x0C, 0x09, 0x43, 0x75, 0x70, 0x65, 0x72, 0x74, 0x69, 0x6E, 0x6F, 0x30, 0x1E, 0x17, 0x0D,
            0x32, 0x33, 0x30, 0x31, 0x30, 0x35, 0x32, 0x31, 0x33, 0x30, 0x32, 0x32, 0x5A, 0x17, 0x0D, 0x33,
            0x33, 0x30, 0x31, 0x30, 0x32, 0x32, 0x31, 0x33, 0x30, 0x32, 0x32, 0x5A, 0x30, 0x36, 0x31, 0x0B,
            0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x13, 0x30, 0x11, 0x06,
            0x03, 0x55, 0x04, 0x08, 0x0C, 0x0A, 0x43, 0x61, 0x6C, 0x69, 0x66, 0x6F, 0x72, 0x6E, 0x69, 0x61,
            0x31, 0x12, 0x30, 0x10, 0x06, 0x03, 0x55, 0x04, 0x07, 0x0C, 0x09, 0x43, 0x75, 0x70, 0x65, 0x72,
            0x74, 0x69, 0x6E, 0x6F, 0x30, 0x59, 0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02,
            0x01, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07, 0x03, 0x42, 0x00, 0x04, 0x73,
            0xEF, 0xC1, 0x97, 0xE8, 0x28, 0xB2, 0x9A, 0x3A, 0xB5, 0xFF, 0x59, 0xEE, 0x2A, 0x39, 0xB5, 0xD2,
            0x9D, 0xAE, 0x53, 0x75, 0x61, 0xD5, 0x67, 0xA8, 0x48, 0x44, 0x0D, 0x70, 0xD2, 0x87, 0x37, 0x40,
            0x24, 0xF4, 0x22, 0x8D, 0xA9, 0x97, 0x20, 0xC1, 0xDF, 0xF3, 0x15, 0x96, 0x4D, 0xAD, 0x73, 0x82,
            0x86, 0x13, 0xC4, 0xE2, 0xA9, 0x6E, 0xE2, 0x6D, 0x0E, 0x99, 0x73, 0xD5, 0x7A, 0xE2, 0x4D, 0xA3,
            0x20, 0x30, 0x1E, 0x30, 0x0C, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x04, 0x05, 0x30, 0x03, 0x01, 0x01,
            0xFF, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x01,
            0x06, 0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03, 0x03, 0x47, 0x00,
            0x30, 0x44, 0x02, 0x20, 0x7A, 0x65, 0x90, 0x5E, 0x73, 0x00, 0x75, 0x36, 0x9D, 0xD8, 0x90, 0xC9,
            0x5A, 0x78, 0x3D, 0x53, 0x8B, 0x81, 0x04, 0xBE, 0x66, 0x03, 0xB5, 0x88, 0xD3, 0x91, 0xFB, 0xA0,
            0x7E, 0xDC, 0xEA, 0x24, 0x02, 0x20, 0x78, 0x91, 0xA8, 0xC8, 0xCD, 0x7F, 0x35, 0x00, 0xCA, 0x2B,
            0xBD, 0x87, 0xAA, 0xCE, 0x53, 0xF2, 0xBE, 0x89, 0x34, 0x74, 0x23, 0xFD, 0xD8, 0xFC, 0xD4, 0x96,
            0xB1, 0x71, 0xD7, 0xF9, 0xA7, 0x1C,
        ]

        #expect(throws: Never.self) { try! X5CVerifier(rootCertificates: [derCertificate]) }
    }

    @Test("Test valid certs")
    func verifyValidCerts() async throws {
        let verifier = try X5CVerifier(rootCertificates: [rootCA])

        let result = try await verifier.verifyChain(
            certificates: [leaf, intermediate],
            policy: {
                RFC5280Policy(fixedExpiryValidationTime: Date(timeIntervalSince1970: TimeInterval(1_681_312_846)))
            }
        )

        switch result {
        case .couldNotValidate(let failures):
            Issue.record("Failed to validate: \(failures)")
        case .validCertificate:
            break
        }
    }

    @Test("Test valid certs with expired validation time")
    func verifyValidCertsWithExpiredValidationTime() async throws {
        let verifier = try X5CVerifier(rootCertificates: [rootCA])

        let result = try await verifier.verifyChain(
            certificates: [leaf, intermediate],
            policy: {
                RFC5280Policy(fixedExpiryValidationTime: Date(timeIntervalSince1970: TimeInterval(2_280_946_846)))
            }
        )

        switch result {
        case .couldNotValidate:
            break
        case .validCertificate:
            Issue.record("Should not have validated")
        }
    }

    @Test("Test signing with x5c chain")
    func signWithX5CChain() async throws {
        let keyCollection = try await JWTKeyCollection()
            .add(
                ecdsa: ES256PrivateKey(pem: x5cLeafCertKey)
            )

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let header: JWTHeader = ["x5c": .array(x5cCerts.map(JWTHeaderField.string))]
        let token = try await keyCollection.sign(payload, header: header)
        let parsed = try DefaultJWTParser().parse(token.bytes, as: TestPayload.self)

        let x5c = try #require(parsed.header.x5c)
        let pemCerts = try x5c.map(getPEMString)
        #expect(pemCerts == x5cCerts)
        let verifier = try X5CVerifier(rootCertificates: [x5cCerts.last!])
        await #expect(throws: Never.self) {
            try await verifier.verifyJWS(token, as: TestPayload.self)
        }
    }

    @Test("Test signing with invalid x5c chain")
    func signWithInvalidX5CChain() async throws {
        let keyCollection = try await JWTKeyCollection()
            .add(
                ecdsa: ES256PrivateKey(pem: x5cLeafCertKey)
            )

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        // Remove the intermediate cert from the chain
        let certs = x5cCerts.enumerated().filter { $0.offset != 1 }.map { $0.element }

        let header: JWTHeader = ["x5c": .array(certs.map(JWTHeaderField.string))]
        let token = try await keyCollection.sign(payload, header: header)
        let parsed = try DefaultJWTParser().parse(token.bytes, as: TestPayload.self)

        let x5c = try #require(parsed.header.x5c)
        let pemCerts = try x5c.map(getPEMString)
        #expect(pemCerts == certs)
        let verifier = try X5CVerifier(rootCertificates: [certs.last!])
        await #expect(throws: (any Error).self) {
            try await verifier.verifyJWS(token, as: TestPayload.self)
        }
    }

    // MARK: Private

    private func getPEMString(from der: String) throws -> String {
        var encoded = der[...]
        let pemLineCount = (encoded.utf8.count + 64) / 64
        var pemLines = [Substring]()
        pemLines.reserveCapacity(pemLineCount + 2)

        pemLines.append("-----BEGIN CERTIFICATE-----")

        while encoded.count > 0 {
            let prefixIndex =
                encoded.index(encoded.startIndex, offsetBy: 64, limitedBy: encoded.endIndex) ?? encoded.endIndex
            pemLines.append(encoded[..<prefixIndex])
            encoded = encoded[prefixIndex...]
        }

        pemLines.append("-----END CERTIFICATE-----")

        return pemLines.joined(separator: "\n")
    }
}

let validToken = """
    eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDZkRDQ0FpT2dBd0lCQWdJVVFxMDhSalpTbnpzSnlCVnlqZFI0R1h1bm1TUXdDZ1lJS29aSXpqMEVBd0l3Z2FFeEN6QUpCZ05WQkFZVEFsVlRNUkV3RHdZRFZRUUlEQWhPWlhjZ1dXOXlhekVSTUE4R0ExVUVCd3dJVG1WM0lGbHZjbXN4RGpBTUJnTlZCQW9NQlZaaGNHOXlNUlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFZU1Cd0dBMVVFQXd3VlZtRndiM0lnU1c1MFpYSnRaV1JwWVhSbElFTkJNU1l3SkFZSktvWklodmNOQVFrQkZoZGhaRzFwYmtCMllYQnZjaTVsZUdGdGNHeGxMbU52YlRBZUZ3MHlOakF5TURreE1qRTFNVFphRncweU56QXlNRGt4TWpFMU1UWmFNSUdXTVFzd0NRWURWUVFHRXdKVlV6RVJNQThHQTFVRUNBd0lUbVYzSUZsdmNtc3hFVEFQQmdOVkJBY01DRTVsZHlCWmIzSnJNUTR3REFZRFZRUUtEQVZXWVhCdmNqRVVNQklHQTFVRUN3d0xSVzVuYVc1bFpYSnBibWN4RXpBUkJnTlZCQU1NQ2xaaGNHOXlJRXhsWVdZeEpqQWtCZ2txaGtpRzl3MEJDUUVXRjJGa2JXbHVRSFpoY0c5eUxtVjRZVzF3YkdVdVkyOXRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVYK0s3TFZhVmpPenFwU3dOK3pqY0NxVDhmMnoyWHUzUE5cL2xjRmthd2IyRURyUXpCNCtiM2VrR1hlcVJmRWc3bGNFMHR6dnhpVmV3RU9TcDNSVktvektOQ01FQXdIUVlEVlIwT0JCWUVGSlF2UCtJR2IzaEdXZW1nZHBLV3B3RE9Vdk5RTUI4R0ExVWRJd1FZTUJhQUZBWXZPRm5FbjdROFNua0FCdDBjOFJLYlFVSnlNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJQnFocEZuUExRdkdjdzdkYXUySU90WmxKeWtNZ2I0WlFCMGpuMEFoeDVKSEFpQTl0cHFWbFR1a1JSMnhjM1dqVlE4NDZHS1BxZElMXC9uXC8yTlVvQ2NJeEZhUT09IiwiTUlJQ2pqQ0NBalNnQXdJQkFnSVVXS3BaWHBiUVRubG1qazhNTUdNcHUxWmtkb2N3Q2dZSUtvWkl6ajBFQXdJd2daa3hDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RVdNQlFHQTFVRUF3d05WbUZ3YjNJZ1VtOXZkQ0JEUVRFbU1DUUdDU3FHU0liM0RRRUpBUllYWVdSdGFXNUFkbUZ3YjNJdVpYaGhiWEJzWlM1amIyMHdIaGNOTWpZd01qQTVNVEl4TlRFMldoY05NekV3TWpBNE1USXhOVEUyV2pDQm9URUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdNQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIREFoT1pYY2dXVzl5YXpFT01Bd0dBMVVFQ2d3RlZtRndiM0l4RkRBU0JnTlZCQXNNQzBWdVoybHVaV1Z5YVc1bk1SNHdIQVlEVlFRRERCVldZWEJ2Y2lCSmJuUmxjbTFsWkdsaGRHVWdRMEV4SmpBa0Jna3Foa2lHOXcwQkNRRVdGMkZrYldsdVFIWmhjRzl5TG1WNFlXMXdiR1V1WTI5dE1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUthaWJtQnFhbzc0bDhwbG1pWDZcL3pLWkE2RjBGeWdBU2p4djY3TG1lQ2g1M2pib0hkQmRKY2RLWnRwY1htWExqbWNVUlRsS1M0anczS1RueDJyK3RwS05RTUU0d0RBWURWUjBUQkFVd0F3RUJcL3pBZEJnTlZIUTRFRmdRVUJpODRXY1NmdER4S2VRQUczUnp4RXB0QlFuSXdId1lEVlIwakJCZ3dGb0FVZVNlUTYyWDdpZGIrbWNMRjNHMHJnQlF5c2Zvd0NnWUlLb1pJemowRUF3SURTQUF3UlFJZ0JUbEUya2pVOHZRQXpXc1wvc1BreXFNVkhiY01nazFGaHp1MVJxaEc5V09JQ0lRQ3hWYWtiaW9udHh6MFplU3pLWFNsbERvZFc2WWhmaU1sbVNIVklrMDBiQVE9PSIsIk1JSUNpVENDQWkrZ0F3SUJBZ0lVQVFubml6em5cL2hJckpCeTN0UEdcL0JzVDh6ZHd3Q2dZSUtvWkl6ajBFQXdJd2daa3hDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RVdNQlFHQTFVRUF3d05WbUZ3YjNJZ1VtOXZkQ0JEUVRFbU1DUUdDU3FHU0liM0RRRUpBUllYWVdSdGFXNUFkbUZ3YjNJdVpYaGhiWEJzWlM1amIyMHdIaGNOTWpZd01qQTVNVEl4TlRFMldoY05Nell3TWpBM01USXhOVEUyV2pDQm1URUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdNQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIREFoT1pYY2dXVzl5YXpFT01Bd0dBMVVFQ2d3RlZtRndiM0l4RkRBU0JnTlZCQXNNQzBWdVoybHVaV1Z5YVc1bk1SWXdGQVlEVlFRRERBMVdZWEJ2Y2lCU2IyOTBJRU5CTVNZd0pBWUpLb1pJaHZjTkFRa0JGaGRoWkcxcGJrQjJZWEJ2Y2k1bGVHRnRjR3hsTG1OdmJUQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJBdG1Bb2RQZmFsSjZsQndqT3R3VVdcL24wYzkydEJXRHRPZGIrU2dIVUhLYnE1dlhybG1Ed2tjamU0NGZYZ1ViSDBmY1wvV3RMXC82dzVwcTU1VWJ6TkMyZWpVekJSTUIwR0ExVWREZ1FXQkJSNUo1RHJaZnVKMXY2WndzWGNiU3VBRkRLeCtqQWZCZ05WSFNNRUdEQVdnQlI1SjVEclpmdUoxdjZad3NYY2JTdUFGREt4K2pBUEJnTlZIUk1CQWY4RUJUQURBUUhcL01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRRHRGeWRiQmhZSXgzWTFjVG8zT2p6Wlp2c0VqWlFhXC8xeUhHeWtcL3VBXC9qXC93SWdNZUpTTnhRRExUR0x2SG9ZWnh0cU80aTJrYytaM0tlZFowa2krWmk0RmswPSJdfQ.eyJjb29sIjp0cnVlfQ.C4htltMFn1cxny-2NQTk6rR-q1wL2Ko0aePc_z8Cb97svkYiLmvLBIpRU7qBC9rHrpLgbidwPPeZUk-qJqn8ew
    """
let validButNotCoolToken = """
    eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDZkRDQ0FpT2dBd0lCQWdJVVFxMDhSalpTbnpzSnlCVnlqZFI0R1h1bm1TUXdDZ1lJS29aSXpqMEVBd0l3Z2FFeEN6QUpCZ05WQkFZVEFsVlRNUkV3RHdZRFZRUUlEQWhPWlhjZ1dXOXlhekVSTUE4R0ExVUVCd3dJVG1WM0lGbHZjbXN4RGpBTUJnTlZCQW9NQlZaaGNHOXlNUlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFZU1Cd0dBMVVFQXd3VlZtRndiM0lnU1c1MFpYSnRaV1JwWVhSbElFTkJNU1l3SkFZSktvWklodmNOQVFrQkZoZGhaRzFwYmtCMllYQnZjaTVsZUdGdGNHeGxMbU52YlRBZUZ3MHlOakF5TURreE1qRTFNVFphRncweU56QXlNRGt4TWpFMU1UWmFNSUdXTVFzd0NRWURWUVFHRXdKVlV6RVJNQThHQTFVRUNBd0lUbVYzSUZsdmNtc3hFVEFQQmdOVkJBY01DRTVsZHlCWmIzSnJNUTR3REFZRFZRUUtEQVZXWVhCdmNqRVVNQklHQTFVRUN3d0xSVzVuYVc1bFpYSnBibWN4RXpBUkJnTlZCQU1NQ2xaaGNHOXlJRXhsWVdZeEpqQWtCZ2txaGtpRzl3MEJDUUVXRjJGa2JXbHVRSFpoY0c5eUxtVjRZVzF3YkdVdVkyOXRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVYK0s3TFZhVmpPenFwU3dOK3pqY0NxVDhmMnoyWHUzUE5cL2xjRmthd2IyRURyUXpCNCtiM2VrR1hlcVJmRWc3bGNFMHR6dnhpVmV3RU9TcDNSVktvektOQ01FQXdIUVlEVlIwT0JCWUVGSlF2UCtJR2IzaEdXZW1nZHBLV3B3RE9Vdk5RTUI4R0ExVWRJd1FZTUJhQUZBWXZPRm5FbjdROFNua0FCdDBjOFJLYlFVSnlNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJQnFocEZuUExRdkdjdzdkYXUySU90WmxKeWtNZ2I0WlFCMGpuMEFoeDVKSEFpQTl0cHFWbFR1a1JSMnhjM1dqVlE4NDZHS1BxZElMXC9uXC8yTlVvQ2NJeEZhUT09IiwiTUlJQ2pqQ0NBalNnQXdJQkFnSVVXS3BaWHBiUVRubG1qazhNTUdNcHUxWmtkb2N3Q2dZSUtvWkl6ajBFQXdJd2daa3hDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RVdNQlFHQTFVRUF3d05WbUZ3YjNJZ1VtOXZkQ0JEUVRFbU1DUUdDU3FHU0liM0RRRUpBUllYWVdSdGFXNUFkbUZ3YjNJdVpYaGhiWEJzWlM1amIyMHdIaGNOTWpZd01qQTVNVEl4TlRFMldoY05NekV3TWpBNE1USXhOVEUyV2pDQm9URUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdNQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIREFoT1pYY2dXVzl5YXpFT01Bd0dBMVVFQ2d3RlZtRndiM0l4RkRBU0JnTlZCQXNNQzBWdVoybHVaV1Z5YVc1bk1SNHdIQVlEVlFRRERCVldZWEJ2Y2lCSmJuUmxjbTFsWkdsaGRHVWdRMEV4SmpBa0Jna3Foa2lHOXcwQkNRRVdGMkZrYldsdVFIWmhjRzl5TG1WNFlXMXdiR1V1WTI5dE1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUthaWJtQnFhbzc0bDhwbG1pWDZcL3pLWkE2RjBGeWdBU2p4djY3TG1lQ2g1M2pib0hkQmRKY2RLWnRwY1htWExqbWNVUlRsS1M0anczS1RueDJyK3RwS05RTUU0d0RBWURWUjBUQkFVd0F3RUJcL3pBZEJnTlZIUTRFRmdRVUJpODRXY1NmdER4S2VRQUczUnp4RXB0QlFuSXdId1lEVlIwakJCZ3dGb0FVZVNlUTYyWDdpZGIrbWNMRjNHMHJnQlF5c2Zvd0NnWUlLb1pJemowRUF3SURTQUF3UlFJZ0JUbEUya2pVOHZRQXpXc1wvc1BreXFNVkhiY01nazFGaHp1MVJxaEc5V09JQ0lRQ3hWYWtiaW9udHh6MFplU3pLWFNsbERvZFc2WWhmaU1sbVNIVklrMDBiQVE9PSIsIk1JSUNpVENDQWkrZ0F3SUJBZ0lVQVFubml6em5cL2hJckpCeTN0UEdcL0JzVDh6ZHd3Q2dZSUtvWkl6ajBFQXdJd2daa3hDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RVdNQlFHQTFVRUF3d05WbUZ3YjNJZ1VtOXZkQ0JEUVRFbU1DUUdDU3FHU0liM0RRRUpBUllYWVdSdGFXNUFkbUZ3YjNJdVpYaGhiWEJzWlM1amIyMHdIaGNOTWpZd01qQTVNVEl4TlRFMldoY05Nell3TWpBM01USXhOVEUyV2pDQm1URUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdNQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIREFoT1pYY2dXVzl5YXpFT01Bd0dBMVVFQ2d3RlZtRndiM0l4RkRBU0JnTlZCQXNNQzBWdVoybHVaV1Z5YVc1bk1SWXdGQVlEVlFRRERBMVdZWEJ2Y2lCU2IyOTBJRU5CTVNZd0pBWUpLb1pJaHZjTkFRa0JGaGRoWkcxcGJrQjJZWEJ2Y2k1bGVHRnRjR3hsTG1OdmJUQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJBdG1Bb2RQZmFsSjZsQndqT3R3VVdcL24wYzkydEJXRHRPZGIrU2dIVUhLYnE1dlhybG1Ed2tjamU0NGZYZ1ViSDBmY1wvV3RMXC82dzVwcTU1VWJ6TkMyZWpVekJSTUIwR0ExVWREZ1FXQkJSNUo1RHJaZnVKMXY2WndzWGNiU3VBRkRLeCtqQWZCZ05WSFNNRUdEQVdnQlI1SjVEclpmdUoxdjZad3NYY2JTdUFGREt4K2pBUEJnTlZIUk1CQWY4RUJUQURBUUhcL01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRRHRGeWRiQmhZSXgzWTFjVG8zT2p6Wlp2c0VqWlFhXC8xeUhHeWtcL3VBXC9qXC93SWdNZUpTTnhRRExUR0x2SG9ZWnh0cU80aTJrYytaM0tlZFowa2krWmk0RmswPSJdfQ.eyJjb29sIjpmYWxzZX0.JIiz90uzJm92xpjokz9XbSpE1FCynH0rT2-dRr0WWVCmosFgL5eBXWyEnYrAIBnRlmFTH5vgzW97ywkQHNqfuA
    """
let missingRootToken = """
    eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDZkRDQ0FpT2dBd0lCQWdJVVFxMDhSalpTbnpzSnlCVnlqZFI0R1h1bm1TUXdDZ1lJS29aSXpqMEVBd0l3Z2FFeEN6QUpCZ05WQkFZVEFsVlRNUkV3RHdZRFZRUUlEQWhPWlhjZ1dXOXlhekVSTUE4R0ExVUVCd3dJVG1WM0lGbHZjbXN4RGpBTUJnTlZCQW9NQlZaaGNHOXlNUlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFZU1Cd0dBMVVFQXd3VlZtRndiM0lnU1c1MFpYSnRaV1JwWVhSbElFTkJNU1l3SkFZSktvWklodmNOQVFrQkZoZGhaRzFwYmtCMllYQnZjaTVsZUdGdGNHeGxMbU52YlRBZUZ3MHlOakF5TURreE1qRTFNVFphRncweU56QXlNRGt4TWpFMU1UWmFNSUdXTVFzd0NRWURWUVFHRXdKVlV6RVJNQThHQTFVRUNBd0lUbVYzSUZsdmNtc3hFVEFQQmdOVkJBY01DRTVsZHlCWmIzSnJNUTR3REFZRFZRUUtEQVZXWVhCdmNqRVVNQklHQTFVRUN3d0xSVzVuYVc1bFpYSnBibWN4RXpBUkJnTlZCQU1NQ2xaaGNHOXlJRXhsWVdZeEpqQWtCZ2txaGtpRzl3MEJDUUVXRjJGa2JXbHVRSFpoY0c5eUxtVjRZVzF3YkdVdVkyOXRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVYK0s3TFZhVmpPenFwU3dOK3pqY0NxVDhmMnoyWHUzUE5cL2xjRmthd2IyRURyUXpCNCtiM2VrR1hlcVJmRWc3bGNFMHR6dnhpVmV3RU9TcDNSVktvektOQ01FQXdIUVlEVlIwT0JCWUVGSlF2UCtJR2IzaEdXZW1nZHBLV3B3RE9Vdk5RTUI4R0ExVWRJd1FZTUJhQUZBWXZPRm5FbjdROFNua0FCdDBjOFJLYlFVSnlNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJQnFocEZuUExRdkdjdzdkYXUySU90WmxKeWtNZ2I0WlFCMGpuMEFoeDVKSEFpQTl0cHFWbFR1a1JSMnhjM1dqVlE4NDZHS1BxZElMXC9uXC8yTlVvQ2NJeEZhUT09IiwiTUlJQ2pqQ0NBalNnQXdJQkFnSVVXS3BaWHBiUVRubG1qazhNTUdNcHUxWmtkb2N3Q2dZSUtvWkl6ajBFQXdJd2daa3hDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RVdNQlFHQTFVRUF3d05WbUZ3YjNJZ1VtOXZkQ0JEUVRFbU1DUUdDU3FHU0liM0RRRUpBUllYWVdSdGFXNUFkbUZ3YjNJdVpYaGhiWEJzWlM1amIyMHdIaGNOTWpZd01qQTVNVEl4TlRFMldoY05NekV3TWpBNE1USXhOVEUyV2pDQm9URUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdNQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIREFoT1pYY2dXVzl5YXpFT01Bd0dBMVVFQ2d3RlZtRndiM0l4RkRBU0JnTlZCQXNNQzBWdVoybHVaV1Z5YVc1bk1SNHdIQVlEVlFRRERCVldZWEJ2Y2lCSmJuUmxjbTFsWkdsaGRHVWdRMEV4SmpBa0Jna3Foa2lHOXcwQkNRRVdGMkZrYldsdVFIWmhjRzl5TG1WNFlXMXdiR1V1WTI5dE1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUthaWJtQnFhbzc0bDhwbG1pWDZcL3pLWkE2RjBGeWdBU2p4djY3TG1lQ2g1M2pib0hkQmRKY2RLWnRwY1htWExqbWNVUlRsS1M0anczS1RueDJyK3RwS05RTUU0d0RBWURWUjBUQkFVd0F3RUJcL3pBZEJnTlZIUTRFRmdRVUJpODRXY1NmdER4S2VRQUczUnp4RXB0QlFuSXdId1lEVlIwakJCZ3dGb0FVZVNlUTYyWDdpZGIrbWNMRjNHMHJnQlF5c2Zvd0NnWUlLb1pJemowRUF3SURTQUF3UlFJZ0JUbEUya2pVOHZRQXpXc1wvc1BreXFNVkhiY01nazFGaHp1MVJxaEc5V09JQ0lRQ3hWYWtiaW9udHh6MFplU3pLWFNsbERvZFc2WWhmaU1sbVNIVklrMDBiQVE9PSJdfQ.eyJjb29sIjp0cnVlfQ.p-rUEo4szaLQPKN158tcJ9K1GzCARZ7CVNoINh_RWvv4qPbGI2p3hh9bRBmLTjsec3gZ2c2P0ISQbq5P0gSBQw
    """
let expiredLeafToken = """
    eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDaERDQ0FpdWdBd0lCQWdJVVFxMDhSalpTbnpzSnlCVnlqZFI0R1h1bm1TVXdDZ1lJS29aSXpqMEVBd0l3Z2FFeEN6QUpCZ05WQkFZVEFsVlRNUkV3RHdZRFZRUUlEQWhPWlhjZ1dXOXlhekVSTUE4R0ExVUVCd3dJVG1WM0lGbHZjbXN4RGpBTUJnTlZCQW9NQlZaaGNHOXlNUlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFZU1Cd0dBMVVFQXd3VlZtRndiM0lnU1c1MFpYSnRaV1JwWVhSbElFTkJNU1l3SkFZSktvWklodmNOQVFrQkZoZGhaRzFwYmtCMllYQnZjaTVsZUdGdGNHeGxMbU52YlRBZUZ3MHlNREF4TURFd01UQXdNREJhRncweU1EQXhNREl3TVRBd01EQmFNSUdlTVFzd0NRWURWUVFHRXdKVlV6RVJNQThHQTFVRUNBd0lUbVYzSUZsdmNtc3hFVEFQQmdOVkJBY01DRTVsZHlCWmIzSnJNUTR3REFZRFZRUUtEQVZXWVhCdmNqRVVNQklHQTFVRUN3d0xSVzVuYVc1bFpYSnBibWN4R3pBWkJnTlZCQU1NRWxaaGNHOXlJRVY0Y0dseVpXUWdUR1ZoWmpFbU1DUUdDU3FHU0liM0RRRUpBUllYWVdSdGFXNUFkbUZ3YjNJdVpYaGhiWEJzWlM1amIyMHdXVEFUQmdjcWhrak9QUUlCQmdncWhrak9QUU1CQndOQ0FBVG1MZkRKZUVMMW5RRGMxVTQ2ZEdFRll0RThTWW5IUVdMR2JXZG5aYkNpSWtuSGNmVVwvYWpQeFg3bDlsZFZ4TzlESHpvRTdtZ3IzODFUSDFiSkJST1wvem8wSXdRREFkQmdOVkhRNEVGZ1FVeVFMNU11OVhhMkQwYXZrVzNxUjhVZFpiZXNNd0h3WURWUjBqQkJnd0ZvQVVCaTg0V2NTZnREeEtlUUFHM1J6eEVwdEJRbkl3Q2dZSUtvWkl6ajBFQXdJRFJ3QXdSQUlnQ0FYUk9aclRCS3hwY2Y2XC9FcUtlOXkxaXVcLzVRY3gwdFJoQzEwOWErNEIwQ0lFNU02WmM3SWJsYUJkajdubzFzMDVKRUJmdHFkM05sSWNLZlFoWFJNcXFlIiwiTUlJQ2pqQ0NBalNnQXdJQkFnSVVXS3BaWHBiUVRubG1qazhNTUdNcHUxWmtkb2N3Q2dZSUtvWkl6ajBFQXdJd2daa3hDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RVdNQlFHQTFVRUF3d05WbUZ3YjNJZ1VtOXZkQ0JEUVRFbU1DUUdDU3FHU0liM0RRRUpBUllYWVdSdGFXNUFkbUZ3YjNJdVpYaGhiWEJzWlM1amIyMHdIaGNOTWpZd01qQTVNVEl4TlRFMldoY05NekV3TWpBNE1USXhOVEUyV2pDQm9URUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdNQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIREFoT1pYY2dXVzl5YXpFT01Bd0dBMVVFQ2d3RlZtRndiM0l4RkRBU0JnTlZCQXNNQzBWdVoybHVaV1Z5YVc1bk1SNHdIQVlEVlFRRERCVldZWEJ2Y2lCSmJuUmxjbTFsWkdsaGRHVWdRMEV4SmpBa0Jna3Foa2lHOXcwQkNRRVdGMkZrYldsdVFIWmhjRzl5TG1WNFlXMXdiR1V1WTI5dE1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRUthaWJtQnFhbzc0bDhwbG1pWDZcL3pLWkE2RjBGeWdBU2p4djY3TG1lQ2g1M2pib0hkQmRKY2RLWnRwY1htWExqbWNVUlRsS1M0anczS1RueDJyK3RwS05RTUU0d0RBWURWUjBUQkFVd0F3RUJcL3pBZEJnTlZIUTRFRmdRVUJpODRXY1NmdER4S2VRQUczUnp4RXB0QlFuSXdId1lEVlIwakJCZ3dGb0FVZVNlUTYyWDdpZGIrbWNMRjNHMHJnQlF5c2Zvd0NnWUlLb1pJemowRUF3SURTQUF3UlFJZ0JUbEUya2pVOHZRQXpXc1wvc1BreXFNVkhiY01nazFGaHp1MVJxaEc5V09JQ0lRQ3hWYWtiaW9udHh6MFplU3pLWFNsbERvZFc2WWhmaU1sbVNIVklrMDBiQVE9PSIsIk1JSUNpVENDQWkrZ0F3SUJBZ0lVQVFubml6em5cL2hJckpCeTN0UEdcL0JzVDh6ZHd3Q2dZSUtvWkl6ajBFQXdJd2daa3hDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RVdNQlFHQTFVRUF3d05WbUZ3YjNJZ1VtOXZkQ0JEUVRFbU1DUUdDU3FHU0liM0RRRUpBUllYWVdSdGFXNUFkbUZ3YjNJdVpYaGhiWEJzWlM1amIyMHdIaGNOTWpZd01qQTVNVEl4TlRFMldoY05Nell3TWpBM01USXhOVEUyV2pDQm1URUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdNQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIREFoT1pYY2dXVzl5YXpFT01Bd0dBMVVFQ2d3RlZtRndiM0l4RkRBU0JnTlZCQXNNQzBWdVoybHVaV1Z5YVc1bk1SWXdGQVlEVlFRRERBMVdZWEJ2Y2lCU2IyOTBJRU5CTVNZd0pBWUpLb1pJaHZjTkFRa0JGaGRoWkcxcGJrQjJZWEJ2Y2k1bGVHRnRjR3hsTG1OdmJUQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJBdG1Bb2RQZmFsSjZsQndqT3R3VVdcL24wYzkydEJXRHRPZGIrU2dIVUhLYnE1dlhybG1Ed2tjamU0NGZYZ1ViSDBmY1wvV3RMXC82dzVwcTU1VWJ6TkMyZWpVekJSTUIwR0ExVWREZ1FXQkJSNUo1RHJaZnVKMXY2WndzWGNiU3VBRkRLeCtqQWZCZ05WSFNNRUdEQVdnQlI1SjVEclpmdUoxdjZad3NYY2JTdUFGREt4K2pBUEJnTlZIUk1CQWY4RUJUQURBUUhcL01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lRRHRGeWRiQmhZSXgzWTFjVG8zT2p6Wlp2c0VqWlFhXC8xeUhHeWtcL3VBXC9qXC93SWdNZUpTTnhRRExUR0x2SG9ZWnh0cU80aTJrYytaM0tlZFowa2krWmk0RmswPSJdfQ.eyJjb29sIjp0cnVlfQ.Be3ee6X-rFoqEV-bO1xXeGbfjBz6ofQDB9gcwLxnACrXbRHefWYUdmC4Ss2pFV6tAZp6BBEcSY5h0NRV96kWRw
    """
let missingLeafToken = """
    eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDampDQ0FqU2dBd0lCQWdJVVdLcFpYcGJRVG5sbWprOE1NR01wdTFaa2RvY3dDZ1lJS29aSXpqMEVBd0l3Z1preEN6QUpCZ05WQkFZVEFsVlRNUkV3RHdZRFZRUUlEQWhPWlhjZ1dXOXlhekVSTUE4R0ExVUVCd3dJVG1WM0lGbHZjbXN4RGpBTUJnTlZCQW9NQlZaaGNHOXlNUlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFV01CUUdBMVVFQXd3TlZtRndiM0lnVW05dmRDQkRRVEVtTUNRR0NTcUdTSWIzRFFFSkFSWVhZV1J0YVc1QWRtRndiM0l1WlhoaGJYQnNaUzVqYjIwd0hoY05Nall3TWpBNU1USXhOVEUyV2hjTk16RXdNakE0TVRJeE5URTJXakNCb1RFTE1Ba0dBMVVFQmhNQ1ZWTXhFVEFQQmdOVkJBZ01DRTVsZHlCWmIzSnJNUkV3RHdZRFZRUUhEQWhPWlhjZ1dXOXlhekVPTUF3R0ExVUVDZ3dGVm1Gd2IzSXhGREFTQmdOVkJBc01DMFZ1WjJsdVpXVnlhVzVuTVI0d0hBWURWUVFEREJWV1lYQnZjaUJKYm5SbGNtMWxaR2xoZEdVZ1EwRXhKakFrQmdrcWhraUc5dzBCQ1FFV0YyRmtiV2x1UUhaaGNHOXlMbVY0WVcxd2JHVXVZMjl0TUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFS2FpYm1CcWFvNzRsOHBsbWlYNlwvektaQTZGMEZ5Z0FTanh2NjdMbWVDaDUzamJvSGRCZEpjZEtadHBjWG1YTGptY1VSVGxLUzRqdzNLVG54MnIrdHBLTlFNRTR3REFZRFZSMFRCQVV3QXdFQlwvekFkQmdOVkhRNEVGZ1FVQmk4NFdjU2Z0RHhLZVFBRzNSenhFcHRCUW5Jd0h3WURWUjBqQkJnd0ZvQVVlU2VRNjJYN2lkYittY0xGM0cwcmdCUXlzZm93Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUlnQlRsRTJralU4dlFBeldzXC9zUGt5cU1WSGJjTWdrMUZoenUxUnFoRzlXT0lDSVFDeFZha2Jpb250eHowWmVTektYU2xsRG9kVzZZaGZpTWxtU0hWSWswMGJBUT09IiwiTUlJQ2lUQ0NBaStnQXdJQkFnSVVBUW5uaXp6blwvaElySkJ5M3RQR1wvQnNUOHpkd3dDZ1lJS29aSXpqMEVBd0l3Z1preEN6QUpCZ05WQkFZVEFsVlRNUkV3RHdZRFZRUUlEQWhPWlhjZ1dXOXlhekVSTUE4R0ExVUVCd3dJVG1WM0lGbHZjbXN4RGpBTUJnTlZCQW9NQlZaaGNHOXlNUlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFV01CUUdBMVVFQXd3TlZtRndiM0lnVW05dmRDQkRRVEVtTUNRR0NTcUdTSWIzRFFFSkFSWVhZV1J0YVc1QWRtRndiM0l1WlhoaGJYQnNaUzVqYjIwd0hoY05Nall3TWpBNU1USXhOVEUyV2hjTk16WXdNakEzTVRJeE5URTJXakNCbVRFTE1Ba0dBMVVFQmhNQ1ZWTXhFVEFQQmdOVkJBZ01DRTVsZHlCWmIzSnJNUkV3RHdZRFZRUUhEQWhPWlhjZ1dXOXlhekVPTUF3R0ExVUVDZ3dGVm1Gd2IzSXhGREFTQmdOVkJBc01DMFZ1WjJsdVpXVnlhVzVuTVJZd0ZBWURWUVFEREExV1lYQnZjaUJTYjI5MElFTkJNU1l3SkFZSktvWklodmNOQVFrQkZoZGhaRzFwYmtCMllYQnZjaTVsZUdGdGNHeGxMbU52YlRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQkF0bUFvZFBmYWxKNmxCd2pPdHdVV1wvbjBjOTJ0QldEdE9kYitTZ0hVSEticTV2WHJsbUR3a2NqZTQ0ZlhnVWJIMGZjXC9XdExcLzZ3NXBxNTVVYnpOQzJlalV6QlJNQjBHQTFVZERnUVdCQlI1SjVEclpmdUoxdjZad3NYY2JTdUFGREt4K2pBZkJnTlZIU01FR0RBV2dCUjVKNURyWmZ1SjF2Nlp3c1hjYlN1QUZES3grakFQQmdOVkhSTUJBZjhFQlRBREFRSFwvTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSVFEdEZ5ZGJCaFlJeDNZMWNUbzNPanpaWnZzRWpaUWFcLzF5SEd5a1wvdUFcL2pcL3dJZ01lSlNOeFFETFRHTHZIb1laeHRxTzRpMmtjK1ozS2VkWjBraStaaTRGazA9Il19.eyJjb29sIjp0cnVlfQ.lwgf9XsfzOzGiNC9pZWUd7vHsIFTupKPAMHVYODIrOQ_ftCGSskeOVyJioTQS1AyMb_xaYDwD86ONELaThYNhg
    """
let missingIntermediateAndRootToken = """
    eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDZkRDQ0FpT2dBd0lCQWdJVVFxMDhSalpTbnpzSnlCVnlqZFI0R1h1bm1TUXdDZ1lJS29aSXpqMEVBd0l3Z2FFeEN6QUpCZ05WQkFZVEFsVlRNUkV3RHdZRFZRUUlEQWhPWlhjZ1dXOXlhekVSTUE4R0ExVUVCd3dJVG1WM0lGbHZjbXN4RGpBTUJnTlZCQW9NQlZaaGNHOXlNUlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFZU1Cd0dBMVVFQXd3VlZtRndiM0lnU1c1MFpYSnRaV1JwWVhSbElFTkJNU1l3SkFZSktvWklodmNOQVFrQkZoZGhaRzFwYmtCMllYQnZjaTVsZUdGdGNHeGxMbU52YlRBZUZ3MHlOakF5TURreE1qRTFNVFphRncweU56QXlNRGt4TWpFMU1UWmFNSUdXTVFzd0NRWURWUVFHRXdKVlV6RVJNQThHQTFVRUNBd0lUbVYzSUZsdmNtc3hFVEFQQmdOVkJBY01DRTVsZHlCWmIzSnJNUTR3REFZRFZRUUtEQVZXWVhCdmNqRVVNQklHQTFVRUN3d0xSVzVuYVc1bFpYSnBibWN4RXpBUkJnTlZCQU1NQ2xaaGNHOXlJRXhsWVdZeEpqQWtCZ2txaGtpRzl3MEJDUUVXRjJGa2JXbHVRSFpoY0c5eUxtVjRZVzF3YkdVdVkyOXRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVYK0s3TFZhVmpPenFwU3dOK3pqY0NxVDhmMnoyWHUzUE5cL2xjRmthd2IyRURyUXpCNCtiM2VrR1hlcVJmRWc3bGNFMHR6dnhpVmV3RU9TcDNSVktvektOQ01FQXdIUVlEVlIwT0JCWUVGSlF2UCtJR2IzaEdXZW1nZHBLV3B3RE9Vdk5RTUI4R0ExVWRJd1FZTUJhQUZBWXZPRm5FbjdROFNua0FCdDBjOFJLYlFVSnlNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJQnFocEZuUExRdkdjdzdkYXUySU90WmxKeWtNZ2I0WlFCMGpuMEFoeDVKSEFpQTl0cHFWbFR1a1JSMnhjM1dqVlE4NDZHS1BxZElMXC9uXC8yTlVvQ2NJeEZhUT09Il19.eyJjb29sIjp0cnVlfQ.2YGSdm0igZP9vHTFAt-kGqVQOhl6nz3cRQVN2wjqVM8tqMRs638IFQDLMVT-F5rVr65B2kUYi84rHpJfPlaoGQ
    """
let missingIntermediateToken = """
    eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDZkRDQ0FpT2dBd0lCQWdJVVFxMDhSalpTbnpzSnlCVnlqZFI0R1h1bm1TUXdDZ1lJS29aSXpqMEVBd0l3Z2FFeEN6QUpCZ05WQkFZVEFsVlRNUkV3RHdZRFZRUUlEQWhPWlhjZ1dXOXlhekVSTUE4R0ExVUVCd3dJVG1WM0lGbHZjbXN4RGpBTUJnTlZCQW9NQlZaaGNHOXlNUlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFZU1Cd0dBMVVFQXd3VlZtRndiM0lnU1c1MFpYSnRaV1JwWVhSbElFTkJNU1l3SkFZSktvWklodmNOQVFrQkZoZGhaRzFwYmtCMllYQnZjaTVsZUdGdGNHeGxMbU52YlRBZUZ3MHlOakF5TURreE1qRTFNVFphRncweU56QXlNRGt4TWpFMU1UWmFNSUdXTVFzd0NRWURWUVFHRXdKVlV6RVJNQThHQTFVRUNBd0lUbVYzSUZsdmNtc3hFVEFQQmdOVkJBY01DRTVsZHlCWmIzSnJNUTR3REFZRFZRUUtEQVZXWVhCdmNqRVVNQklHQTFVRUN3d0xSVzVuYVc1bFpYSnBibWN4RXpBUkJnTlZCQU1NQ2xaaGNHOXlJRXhsWVdZeEpqQWtCZ2txaGtpRzl3MEJDUUVXRjJGa2JXbHVRSFpoY0c5eUxtVjRZVzF3YkdVdVkyOXRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUVYK0s3TFZhVmpPenFwU3dOK3pqY0NxVDhmMnoyWHUzUE5cL2xjRmthd2IyRURyUXpCNCtiM2VrR1hlcVJmRWc3bGNFMHR6dnhpVmV3RU9TcDNSVktvektOQ01FQXdIUVlEVlIwT0JCWUVGSlF2UCtJR2IzaEdXZW1nZHBLV3B3RE9Vdk5RTUI4R0ExVWRJd1FZTUJhQUZBWXZPRm5FbjdROFNua0FCdDBjOFJLYlFVSnlNQW9HQ0NxR1NNNDlCQU1DQTBjQU1FUUNJQnFocEZuUExRdkdjdzdkYXUySU90WmxKeWtNZ2I0WlFCMGpuMEFoeDVKSEFpQTl0cHFWbFR1a1JSMnhjM1dqVlE4NDZHS1BxZElMXC9uXC8yTlVvQ2NJeEZhUT09IiwiTUlJQ2lUQ0NBaStnQXdJQkFnSVVBUW5uaXp6blwvaElySkJ5M3RQR1wvQnNUOHpkd3dDZ1lJS29aSXpqMEVBd0l3Z1preEN6QUpCZ05WQkFZVEFsVlRNUkV3RHdZRFZRUUlEQWhPWlhjZ1dXOXlhekVSTUE4R0ExVUVCd3dJVG1WM0lGbHZjbXN4RGpBTUJnTlZCQW9NQlZaaGNHOXlNUlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFV01CUUdBMVVFQXd3TlZtRndiM0lnVW05dmRDQkRRVEVtTUNRR0NTcUdTSWIzRFFFSkFSWVhZV1J0YVc1QWRtRndiM0l1WlhoaGJYQnNaUzVqYjIwd0hoY05Nall3TWpBNU1USXhOVEUyV2hjTk16WXdNakEzTVRJeE5URTJXakNCbVRFTE1Ba0dBMVVFQmhNQ1ZWTXhFVEFQQmdOVkJBZ01DRTVsZHlCWmIzSnJNUkV3RHdZRFZRUUhEQWhPWlhjZ1dXOXlhekVPTUF3R0ExVUVDZ3dGVm1Gd2IzSXhGREFTQmdOVkJBc01DMFZ1WjJsdVpXVnlhVzVuTVJZd0ZBWURWUVFEREExV1lYQnZjaUJTYjI5MElFTkJNU1l3SkFZSktvWklodmNOQVFrQkZoZGhaRzFwYmtCMllYQnZjaTVsZUdGdGNHeGxMbU52YlRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQkF0bUFvZFBmYWxKNmxCd2pPdHdVV1wvbjBjOTJ0QldEdE9kYitTZ0hVSEticTV2WHJsbUR3a2NqZTQ0ZlhnVWJIMGZjXC9XdExcLzZ3NXBxNTVVYnpOQzJlalV6QlJNQjBHQTFVZERnUVdCQlI1SjVEclpmdUoxdjZad3NYY2JTdUFGREt4K2pBZkJnTlZIU01FR0RBV2dCUjVKNURyWmZ1SjF2Nlp3c1hjYlN1QUZES3grakFQQmdOVkhSTUJBZjhFQlRBREFRSFwvTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSVFEdEZ5ZGJCaFlJeDNZMWNUbzNPanpaWnZzRWpaUWFcLzF5SEd5a1wvdUFcL2pcL3dJZ01lSlNOeFFETFRHTHZIb1laeHRxTzRpMmtjK1ozS2VkWjBraStaaTRGazA9Il19.eyJjb29sIjp0cnVlfQ.ZdIvEHoATSQTe_v9lNy7_sT4fF2Yronr7Xfqba4oI9h_FCntoZmB_DNcxfx3zA2B9uXe2n-3ft-L6N4tyrHiUg
    """
let missingLeafAndIntermediateToken = """
    eyJ0eXAiOiJKV1QiLCJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDaVRDQ0FpK2dBd0lCQWdJVUFRbm5penpuXC9oSXJKQnkzdFBHXC9Cc1Q4emR3d0NnWUlLb1pJemowRUF3SXdnWmt4Q3pBSkJnTlZCQVlUQWxWVE1SRXdEd1lEVlFRSURBaE9aWGNnV1c5eWF6RVJNQThHQTFVRUJ3d0lUbVYzSUZsdmNtc3hEakFNQmdOVkJBb01CVlpoY0c5eU1SUXdFZ1lEVlFRTERBdEZibWRwYm1WbGNtbHVaekVXTUJRR0ExVUVBd3dOVm1Gd2IzSWdVbTl2ZENCRFFURW1NQ1FHQ1NxR1NJYjNEUUVKQVJZWFlXUnRhVzVBZG1Gd2IzSXVaWGhoYlhCc1pTNWpiMjB3SGhjTk1qWXdNakE1TVRJeE5URTJXaGNOTXpZd01qQTNNVEl4TlRFMldqQ0JtVEVMTUFrR0ExVUVCaE1DVlZNeEVUQVBCZ05WQkFnTUNFNWxkeUJaYjNKck1SRXdEd1lEVlFRSERBaE9aWGNnV1c5eWF6RU9NQXdHQTFVRUNnd0ZWbUZ3YjNJeEZEQVNCZ05WQkFzTUMwVnVaMmx1WldWeWFXNW5NUll3RkFZRFZRUUREQTFXWVhCdmNpQlNiMjkwSUVOQk1TWXdKQVlKS29aSWh2Y05BUWtCRmhkaFpHMXBia0IyWVhCdmNpNWxlR0Z0Y0d4bExtTnZiVEJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCQXRtQW9kUGZhbEo2bEJ3ak90d1VXXC9uMGM5MnRCV0R0T2RiK1NnSFVIS2JxNXZYcmxtRHdrY2plNDRmWGdVYkgwZmNcL1d0TFwvNnc1cHE1NVViek5DMmVqVXpCUk1CMEdBMVVkRGdRV0JCUjVKNURyWmZ1SjF2Nlp3c1hjYlN1QUZES3grakFmQmdOVkhTTUVHREFXZ0JSNUo1RHJaZnVKMXY2WndzWGNiU3VBRkRLeCtqQVBCZ05WSFJNQkFmOEVCVEFEQVFIXC9NQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJUUR0RnlkYkJoWUl4M1kxY1RvM09qelpadnNFalpRYVwvMXlIR3lrXC91QVwvalwvd0lnTWVKU054UURMVEdMdkhvWVp4dHFPNGkya2MrWjNLZWRaMGtpK1ppNEZrMD0iXX0.eyJjb29sIjp0cnVlfQ.nBm2ew-bknfjH8DyHdLJOL4I7T6gJtvxEpLypg6jel1ELz2eYQxljNr6l1ra83W1IEi9lSNFAYeq9mR3uPVwWg
    """

let x5cCerts = [
    """
    -----BEGIN CERTIFICATE-----
    MIICfDCCAiOgAwIBAgIUQq08RjZSnzsJyBVyjdR4GXunmSQwCgYIKoZIzj0EAwIw
    gaExCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhOZXcgWW9yazERMA8GA1UEBwwITmV3
    IFlvcmsxDjAMBgNVBAoMBVZhcG9yMRQwEgYDVQQLDAtFbmdpbmVlcmluZzEeMBwG
    A1UEAwwVVmFwb3IgSW50ZXJtZWRpYXRlIENBMSYwJAYJKoZIhvcNAQkBFhdhZG1p
    bkB2YXBvci5leGFtcGxlLmNvbTAeFw0yNjAyMDkxMjE1MTZaFw0yNzAyMDkxMjE1
    MTZaMIGWMQswCQYDVQQGEwJVUzERMA8GA1UECAwITmV3IFlvcmsxETAPBgNVBAcM
    CE5ldyBZb3JrMQ4wDAYDVQQKDAVWYXBvcjEUMBIGA1UECwwLRW5naW5lZXJpbmcx
    EzARBgNVBAMMClZhcG9yIExlYWYxJjAkBgkqhkiG9w0BCQEWF2FkbWluQHZhcG9y
    LmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEX+K7LVaVjOzq
    pSwN+zjcCqT8f2z2Xu3PN/lcFkawb2EDrQzB4+b3ekGXeqRfEg7lcE0tzvxiVewE
    OSp3RVKozKNCMEAwHQYDVR0OBBYEFJQvP+IGb3hGWemgdpKWpwDOUvNQMB8GA1Ud
    IwQYMBaAFAYvOFnEn7Q8SnkABt0c8RKbQUJyMAoGCCqGSM49BAMCA0cAMEQCIBqh
    pFnPLQvGcw7dau2IOtZlJykMgb4ZQB0jn0Ahx5JHAiA9tpqVlTukRR2xc3WjVQ84
    6GKPqdIL/n/2NUoCcIxFaQ==
    -----END CERTIFICATE-----
    """,
    """
    -----BEGIN CERTIFICATE-----
    MIICjjCCAjSgAwIBAgIUWKpZXpbQTnlmjk8MMGMpu1ZkdocwCgYIKoZIzj0EAwIw
    gZkxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhOZXcgWW9yazERMA8GA1UEBwwITmV3
    IFlvcmsxDjAMBgNVBAoMBVZhcG9yMRQwEgYDVQQLDAtFbmdpbmVlcmluZzEWMBQG
    A1UEAwwNVmFwb3IgUm9vdCBDQTEmMCQGCSqGSIb3DQEJARYXYWRtaW5AdmFwb3Iu
    ZXhhbXBsZS5jb20wHhcNMjYwMjA5MTIxNTE2WhcNMzEwMjA4MTIxNTE2WjCBoTEL
    MAkGA1UEBhMCVVMxETAPBgNVBAgMCE5ldyBZb3JrMREwDwYDVQQHDAhOZXcgWW9y
    azEOMAwGA1UECgwFVmFwb3IxFDASBgNVBAsMC0VuZ2luZWVyaW5nMR4wHAYDVQQD
    DBVWYXBvciBJbnRlcm1lZGlhdGUgQ0ExJjAkBgkqhkiG9w0BCQEWF2FkbWluQHZh
    cG9yLmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEKaibmBqa
    o74l8plmiX6/zKZA6F0FygASjxv67LmeCh53jboHdBdJcdKZtpcXmXLjmcURTlKS
    4jw3KTnx2r+tpKNQME4wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUBi84WcSftDxK
    eQAG3RzxEptBQnIwHwYDVR0jBBgwFoAUeSeQ62X7idb+mcLF3G0rgBQysfowCgYI
    KoZIzj0EAwIDSAAwRQIgBTlE2kjU8vQAzWs/sPkyqMVHbcMgk1Fhzu1RqhG9WOIC
    IQCxVakbiontxz0ZeSzKXSllDodW6YhfiMlmSHVIk00bAQ==
    -----END CERTIFICATE-----
    """,
    """
    -----BEGIN CERTIFICATE-----
    MIICiTCCAi+gAwIBAgIUAQnnizzn/hIrJBy3tPG/BsT8zdwwCgYIKoZIzj0EAwIw
    gZkxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhOZXcgWW9yazERMA8GA1UEBwwITmV3
    IFlvcmsxDjAMBgNVBAoMBVZhcG9yMRQwEgYDVQQLDAtFbmdpbmVlcmluZzEWMBQG
    A1UEAwwNVmFwb3IgUm9vdCBDQTEmMCQGCSqGSIb3DQEJARYXYWRtaW5AdmFwb3Iu
    ZXhhbXBsZS5jb20wHhcNMjYwMjA5MTIxNTE2WhcNMzYwMjA3MTIxNTE2WjCBmTEL
    MAkGA1UEBhMCVVMxETAPBgNVBAgMCE5ldyBZb3JrMREwDwYDVQQHDAhOZXcgWW9y
    azEOMAwGA1UECgwFVmFwb3IxFDASBgNVBAsMC0VuZ2luZWVyaW5nMRYwFAYDVQQD
    DA1WYXBvciBSb290IENBMSYwJAYJKoZIhvcNAQkBFhdhZG1pbkB2YXBvci5leGFt
    cGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABAtmAodPfalJ6lBwjOtw
    UW/n0c92tBWDtOdb+SgHUHKbq5vXrlmDwkcje44fXgUbH0fc/WtL/6w5pq55UbzN
    C2ejUzBRMB0GA1UdDgQWBBR5J5DrZfuJ1v6ZwsXcbSuAFDKx+jAfBgNVHSMEGDAW
    gBR5J5DrZfuJ1v6ZwsXcbSuAFDKx+jAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49
    BAMCA0gAMEUCIQDtFydbBhYIx3Y1cTo3OjzZZvsEjZQa/1yHGyk/uA/j/wIgMeJS
    NxQDLTGLvHoYZxtqO4i2kc+Z3KedZ0ki+Zi4Fk0=
    -----END CERTIFICATE-----
    """,
]

let x5cLeafCertKey = """
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEII3IvhB0iWEU8xIjMWbktVbeQ+K6458CjKjJvhuR13a5oAoGCCqGSM49
    AwEHoUQDQgAEX+K7LVaVjOzqpSwN+zjcCqT8f2z2Xu3PN/lcFkawb2EDrQzB4+b3
    ekGXeqRfEg7lcE0tzvxiVewEOSp3RVKozA==
    -----END EC PRIVATE KEY-----
    """

let rootCA = try! Certificate(
    derEncoded: Array(
        Data(
            base64Encoded:
                "MIIBgjCCASmgAwIBAgIJALUc5ALiH5pbMAoGCCqGSM49BAMDMDYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDdXBlcnRpbm8wHhcNMjMwMTA1MjEzMDIyWhcNMzMwMTAyMjEzMDIyWjA2MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJQ3VwZXJ0aW5vMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc+/Bl+gospo6tf9Z7io5tdKdrlN1YdVnqEhEDXDShzdAJPQijamXIMHf8xWWTa1zgoYTxOKpbuJtDplz1XriTaMgMB4wDAYDVR0TBAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDRwAwRAIgemWQXnMAdTad2JDJWng9U4uBBL5mA7WI05H7oH7c6iQCIHiRqMjNfzUAyiu9h6rOU/K+iTR0I/3Y/NSWsXHX+acc"
        )!
    )
)
let leaf = try! Certificate(
    derEncoded: Array(
        Data(
            base64Encoded:
                "MIIBoDCCAUagAwIBAgIBDDAKBggqhkjOPQQDAzBFMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExEjAQBgNVBAcMCUN1cGVydGlubzEVMBMGA1UECgwMSW50ZXJtZWRpYXRlMB4XDTIzMDEwNTIxMzEzNFoXDTMzMDEwMTIxMzEzNFowPTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYDVQQHDAlDdXBlcnRpbm8xDTALBgNVBAoMBExlYWYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATitYHEaYVuc8g9AjTOwErMvGyPykPa+puvTI8hJTHZZDLGas2qX1+ErxgQTJgVXv76nmLhhRJH+j25AiAI8iGsoy8wLTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIHgDAQBgoqhkiG92NkBgsBBAIFADAKBggqhkjOPQQDAwNIADBFAiBX4c+T0Fp5nJ5QRClRfu5PSByRvNPtuaTsk0vPB3WAIAIhANgaauAj/YP9s0AkEhyJhxQO/6Q2zouZ+H1CIOehnMzQ"
        )!
    )
)
let intermediate = try! Certificate(
    derEncoded: Array(
        Data(
            base64Encoded:
                "MIIBnzCCAUWgAwIBAgIBCzAKBggqhkjOPQQDAzA2MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJQ3VwZXJ0aW5vMB4XDTIzMDEwNTIxMzEwNVoXDTMzMDEwMTIxMzEwNVowRTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYDVQQHDAlDdXBlcnRpbm8xFTATBgNVBAoMDEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBUN5V9rKjfRiMAIojEA0Av5Mp0oF+O0cL4gzrTF178inUHugj7Et46NrkQ7hKgMVnjogq45Q1rMs+cMHVNILWqjNTAzMA8GA1UdEwQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMBAGCiqGSIb3Y2QGAgEEAgUAMAoGCCqGSM49BAMDA0gAMEUCIQCmsIKYs41ullssHX4rVveUT0Z7Is5/hLK1lFPTtun3hAIgc2+2RG5+gNcFVcs+XJeEl4GZ+ojl3ROOmll+ye7dynQ="
        )!
    )
)

/// Each token has the following payload:
///
///     {
///        "cool" : true
///     }
private struct TokenPayload: JWTPayload {
    var cool: BoolClaim

    func verify(using _: some JWTAlgorithm) throws {
        if !cool.value {
            throw JWTError.claimVerificationFailure(failedClaim: self.cool, reason: "not cool")
        }
    }
}
#endif  // canImport(Testing)
