#if canImport(Testing)
import Testing
import JWTKit
import X509

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
        MIICijCCAi+gAwIBAgIUQ+GZt69343+8jDCMflUIG4Il2MswCgYIKoZIzj0EAwIw
        gZkxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhOZXcgWW9yazERMA8GA1UEBwwITmV3
        IFlvcmsxDjAMBgNVBAoMBVZhcG9yMRQwEgYDVQQLDAtFbmdpbmVlcmluZzEWMBQG
        A1UEAwwNVmFwb3IgUm9vdCBDQTEmMCQGCSqGSIb3DQEJARYXYWRtaW5AdmFwb3Iu
        ZXhhbXBsZS5jb20wHhcNMjUwMTEwMDkyNzE4WhcNMzUwMTA4MDkyNzE4WjCBmTEL
        MAkGA1UEBhMCVVMxETAPBgNVBAgMCE5ldyBZb3JrMREwDwYDVQQHDAhOZXcgWW9y
        azEOMAwGA1UECgwFVmFwb3IxFDASBgNVBAsMC0VuZ2luZWVyaW5nMRYwFAYDVQQD
        DA1WYXBvciBSb290IENBMSYwJAYJKoZIhvcNAQkBFhdhZG1pbkB2YXBvci5leGFt
        cGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABK/74uVxo9bVpbF13l3d
        h7txUH20FpOwW7JsNvW6yGzRrJr0JcGIUJFUml8horg/mZLQqde+LTKf4VByWlk7
        hBKjUzBRMB0GA1UdDgQWBBTwox5TK8yr7ZDJcieuEo6hOUJvcjAfBgNVHSMEGDAW
        gBTwox5TK8yr7ZDJcieuEo6hOUJvcjAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49
        BAMCA0kAMEYCIQDDB3s+2CUl/YrXxQUbyl38GNSpXcogYfEcWXEQmQtOlgIhAJHz
        e7CCTDHODtGan89r2VED7tXpwGk/5EWLarTvohI3
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
                RFC5280Policy(validationTime: Date(timeIntervalSince1970: TimeInterval(1_681_312_846)))
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
                RFC5280Policy(validationTime: Date(timeIntervalSince1970: TimeInterval(2_280_946_846)))
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

let missingIntermediateToken = """
    eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlDZmpDQ0FpT2dBd0lCQWdJVUZ5b29aUm1zXC9TUzVKdllMMGRsNmhId1I1bFl3Q2dZSUtvWkl6ajBFQXdJd2dhRXhDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RWVNQndHQTFVRUF3d1ZWbUZ3YjNJZ1NXNTBaWEp0WldScFlYUmxJRU5CTVNZd0pBWUpLb1pJaHZjTkFRa0JGaGRoWkcxcGJrQjJZWEJ2Y2k1bGVHRnRjR3hsTG1OdmJUQWVGdzB5TlRBeE1UQXdPVEkzTVRoYUZ3MHlOakF4TVRBd09USTNNVGhhTUlHV01Rc3dDUVlEVlFRR0V3SlZVekVSTUE4R0ExVUVDQXdJVG1WM0lGbHZjbXN4RVRBUEJnTlZCQWNNQ0U1bGR5QlpiM0pyTVE0d0RBWURWUVFLREFWV1lYQnZjakVVTUJJR0ExVUVDd3dMUlc1bmFXNWxaWEpwYm1jeEV6QVJCZ05WQkFNTUNsWmhjRzl5SUV4bFlXWXhKakFrQmdrcWhraUc5dzBCQ1FFV0YyRmtiV2x1UUhaaGNHOXlMbVY0WVcxd2JHVXVZMjl0TUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFWExLUHNkMVBpczE4Wno3NzlMSTNqZTRHQ1wvR0xlZUp4eFM3VjVud0Z4U0F0U3htSlhaUGx3RDZjZEZydVhkd0p2ekpuT1ByWFdENHBZdkFNUFwvN0NTNk5DTUVBd0hRWURWUjBPQkJZRUZIXC9ja0Z0bWtKYll5aXZ5VmtvdHAyRklwTnFXTUI4R0ExVWRJd1FZTUJhQUZIUFd6am43SHhHSTJ4SHhSTkVKaHkzU1JJZVZNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUURSd1g4TTZEVEgwSmVjZGNSdDBYVTdXUlhXZkZvRUZmbGRrTFJKOVU0dlFRSWhBTHBWUFhVSVozTEx2MVVTYlk3M0pRNWNrMEk3OTJjdTVcL25hQ2VUNm84ckgiLCJNSUlDaWpDQ0FpK2dBd0lCQWdJVVErR1p0NjkzNDMrOGpEQ01mbFVJRzRJbDJNc3dDZ1lJS29aSXpqMEVBd0l3Z1preEN6QUpCZ05WQkFZVEFsVlRNUkV3RHdZRFZRUUlEQWhPWlhjZ1dXOXlhekVSTUE4R0ExVUVCd3dJVG1WM0lGbHZjbXN4RGpBTUJnTlZCQW9NQlZaaGNHOXlNUlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFV01CUUdBMVVFQXd3TlZtRndiM0lnVW05dmRDQkRRVEVtTUNRR0NTcUdTSWIzRFFFSkFSWVhZV1J0YVc1QWRtRndiM0l1WlhoaGJYQnNaUzVqYjIwd0hoY05NalV3TVRFd01Ea3lOekU0V2hjTk16VXdNVEE0TURreU56RTRXakNCbVRFTE1Ba0dBMVVFQmhNQ1ZWTXhFVEFQQmdOVkJBZ01DRTVsZHlCWmIzSnJNUkV3RHdZRFZRUUhEQWhPWlhjZ1dXOXlhekVPTUF3R0ExVUVDZ3dGVm1Gd2IzSXhGREFTQmdOVkJBc01DMFZ1WjJsdVpXVnlhVzVuTVJZd0ZBWURWUVFEREExV1lYQnZjaUJTYjI5MElFTkJNU1l3SkFZSktvWklodmNOQVFrQkZoZGhaRzFwYmtCMllYQnZjaTVsZUdGdGNHeGxMbU52YlRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQktcLzc0dVZ4bzliVnBiRjEzbDNkaDd0eFVIMjBGcE93VzdKc052VzZ5R3pSckpyMEpjR0lVSkZVbWw4aG9yZ1wvbVpMUXFkZStMVEtmNFZCeVdsazdoQktqVXpCUk1CMEdBMVVkRGdRV0JCVHdveDVUSzh5cjdaREpjaWV1RW82aE9VSnZjakFmQmdOVkhTTUVHREFXZ0JUd294NVRLOHlyN1pESmNpZXVFbzZoT1VKdmNqQVBCZ05WSFJNQkFmOEVCVEFEQVFIXC9NQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUUREQjNzKzJDVWxcL1lyWHhRVWJ5bDM4R05TcFhjb2dZZkVjV1hFUW1RdE9sZ0loQUpIemU3Q0NUREhPRHRHYW44OXIyVkVEN3RYcHdHa1wvNUVXTGFyVHZvaEkzIl19.eyJjb29sIjp0cnVlfQ.Mr5vTqM97-hdniDt1kZWXZcyKQ_7tBKlh8bCwMhubyPk0TDuvbzb14bu1iOJY9KtVwxdZQqkUxLijhAKi8hHPg
    """
let missingRootToken = """
    eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlDZmpDQ0FpT2dBd0lCQWdJVUZ5b29aUm1zXC9TUzVKdllMMGRsNmhId1I1bFl3Q2dZSUtvWkl6ajBFQXdJd2dhRXhDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RWVNQndHQTFVRUF3d1ZWbUZ3YjNJZ1NXNTBaWEp0WldScFlYUmxJRU5CTVNZd0pBWUpLb1pJaHZjTkFRa0JGaGRoWkcxcGJrQjJZWEJ2Y2k1bGVHRnRjR3hsTG1OdmJUQWVGdzB5TlRBeE1UQXdPVEkzTVRoYUZ3MHlOakF4TVRBd09USTNNVGhhTUlHV01Rc3dDUVlEVlFRR0V3SlZVekVSTUE4R0ExVUVDQXdJVG1WM0lGbHZjbXN4RVRBUEJnTlZCQWNNQ0U1bGR5QlpiM0pyTVE0d0RBWURWUVFLREFWV1lYQnZjakVVTUJJR0ExVUVDd3dMUlc1bmFXNWxaWEpwYm1jeEV6QVJCZ05WQkFNTUNsWmhjRzl5SUV4bFlXWXhKakFrQmdrcWhraUc5dzBCQ1FFV0YyRmtiV2x1UUhaaGNHOXlMbVY0WVcxd2JHVXVZMjl0TUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFWExLUHNkMVBpczE4Wno3NzlMSTNqZTRHQ1wvR0xlZUp4eFM3VjVud0Z4U0F0U3htSlhaUGx3RDZjZEZydVhkd0p2ekpuT1ByWFdENHBZdkFNUFwvN0NTNk5DTUVBd0hRWURWUjBPQkJZRUZIXC9ja0Z0bWtKYll5aXZ5VmtvdHAyRklwTnFXTUI4R0ExVWRJd1FZTUJhQUZIUFd6am43SHhHSTJ4SHhSTkVKaHkzU1JJZVZNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUURSd1g4TTZEVEgwSmVjZGNSdDBYVTdXUlhXZkZvRUZmbGRrTFJKOVU0dlFRSWhBTHBWUFhVSVozTEx2MVVTYlk3M0pRNWNrMEk3OTJjdTVcL25hQ2VUNm84ckgiLCJNSUlDampDQ0FqU2dBd0lCQWdJVVM1Uk1IUVNQOTFFWkhaRzlHTG1LcFNcL0NxYm93Q2dZSUtvWkl6ajBFQXdJd2daa3hDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RVdNQlFHQTFVRUF3d05WbUZ3YjNJZ1VtOXZkQ0JEUVRFbU1DUUdDU3FHU0liM0RRRUpBUllYWVdSdGFXNUFkbUZ3YjNJdVpYaGhiWEJzWlM1amIyMHdIaGNOTWpVd01URXdNRGt5TnpFNFdoY05NekF3TVRBNU1Ea3lOekU0V2pDQm9URUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdNQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIREFoT1pYY2dXVzl5YXpFT01Bd0dBMVVFQ2d3RlZtRndiM0l4RkRBU0JnTlZCQXNNQzBWdVoybHVaV1Z5YVc1bk1SNHdIQVlEVlFRRERCVldZWEJ2Y2lCSmJuUmxjbTFsWkdsaGRHVWdRMEV4SmpBa0Jna3Foa2lHOXcwQkNRRVdGMkZrYldsdVFIWmhjRzl5TG1WNFlXMXdiR1V1WTI5dE1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRXR2c1JaTmFvWXhlME9FY3lTcDRQanQxWjF4NmJ2VVwvYU5PVVdjazVpZEJpWHpMZnExYXREaGpsNVpSUEFOSWozeXI3aGw0clNrZ3FramFiQXJLY250S05RTUU0d0RBWURWUjBUQkFVd0F3RUJcL3pBZEJnTlZIUTRFRmdRVWM5Yk9PZnNmRVlqYkVmRkUwUW1ITGRKRWg1VXdId1lEVlIwakJCZ3dGb0FVOEtNZVV5dk1xKzJReVhJbnJoS09vVGxDYjNJd0NnWUlLb1pJemowRUF3SURTQUF3UlFJaEFOVFFaVGxvdCtQSGk5a2NzbHl1ZHdqSXFaNTdVbms2VXdwVHJ4Wm40bXQxQWlBd3poaW5jUHNvSE5FWnIrdEFFZmtOb0crMzVGVG9jbElxV0F4aVErMnpNdz09Il19.eyJjb29sIjp0cnVlfQ.TLleai7BXhSfpFQ1j0eCKxNlKFtcTIO3nlBixeaeCnrnu2xGNVTX2zdTjJCd32udiLm9Kx4qihIguU9IwKX9Ag
    """
let validButNotCoolToken = """
    eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDZmpDQ0FpT2dBd0lCQWdJVUZ5b29aUm1zXC9TUzVKdllMMGRsNmhId1I1bFl3Q2dZSUtvWkl6ajBFQXdJd2dhRXhDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RWVNQndHQTFVRUF3d1ZWbUZ3YjNJZ1NXNTBaWEp0WldScFlYUmxJRU5CTVNZd0pBWUpLb1pJaHZjTkFRa0JGaGRoWkcxcGJrQjJZWEJ2Y2k1bGVHRnRjR3hsTG1OdmJUQWVGdzB5TlRBeE1UQXdPVEkzTVRoYUZ3MHlOakF4TVRBd09USTNNVGhhTUlHV01Rc3dDUVlEVlFRR0V3SlZVekVSTUE4R0ExVUVDQXdJVG1WM0lGbHZjbXN4RVRBUEJnTlZCQWNNQ0U1bGR5QlpiM0pyTVE0d0RBWURWUVFLREFWV1lYQnZjakVVTUJJR0ExVUVDd3dMUlc1bmFXNWxaWEpwYm1jeEV6QVJCZ05WQkFNTUNsWmhjRzl5SUV4bFlXWXhKakFrQmdrcWhraUc5dzBCQ1FFV0YyRmtiV2x1UUhaaGNHOXlMbVY0WVcxd2JHVXVZMjl0TUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFWExLUHNkMVBpczE4Wno3NzlMSTNqZTRHQ1wvR0xlZUp4eFM3VjVud0Z4U0F0U3htSlhaUGx3RDZjZEZydVhkd0p2ekpuT1ByWFdENHBZdkFNUFwvN0NTNk5DTUVBd0hRWURWUjBPQkJZRUZIXC9ja0Z0bWtKYll5aXZ5VmtvdHAyRklwTnFXTUI4R0ExVWRJd1FZTUJhQUZIUFd6am43SHhHSTJ4SHhSTkVKaHkzU1JJZVZNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUURSd1g4TTZEVEgwSmVjZGNSdDBYVTdXUlhXZkZvRUZmbGRrTFJKOVU0dlFRSWhBTHBWUFhVSVozTEx2MVVTYlk3M0pRNWNrMEk3OTJjdTVcL25hQ2VUNm84ckgiLCJNSUlDampDQ0FqU2dBd0lCQWdJVVM1Uk1IUVNQOTFFWkhaRzlHTG1LcFNcL0NxYm93Q2dZSUtvWkl6ajBFQXdJd2daa3hDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RVdNQlFHQTFVRUF3d05WbUZ3YjNJZ1VtOXZkQ0JEUVRFbU1DUUdDU3FHU0liM0RRRUpBUllYWVdSdGFXNUFkbUZ3YjNJdVpYaGhiWEJzWlM1amIyMHdIaGNOTWpVd01URXdNRGt5TnpFNFdoY05NekF3TVRBNU1Ea3lOekU0V2pDQm9URUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdNQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIREFoT1pYY2dXVzl5YXpFT01Bd0dBMVVFQ2d3RlZtRndiM0l4RkRBU0JnTlZCQXNNQzBWdVoybHVaV1Z5YVc1bk1SNHdIQVlEVlFRRERCVldZWEJ2Y2lCSmJuUmxjbTFsWkdsaGRHVWdRMEV4SmpBa0Jna3Foa2lHOXcwQkNRRVdGMkZrYldsdVFIWmhjRzl5TG1WNFlXMXdiR1V1WTI5dE1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRXR2c1JaTmFvWXhlME9FY3lTcDRQanQxWjF4NmJ2VVwvYU5PVVdjazVpZEJpWHpMZnExYXREaGpsNVpSUEFOSWozeXI3aGw0clNrZ3FramFiQXJLY250S05RTUU0d0RBWURWUjBUQkFVd0F3RUJcL3pBZEJnTlZIUTRFRmdRVWM5Yk9PZnNmRVlqYkVmRkUwUW1ITGRKRWg1VXdId1lEVlIwakJCZ3dGb0FVOEtNZVV5dk1xKzJReVhJbnJoS09vVGxDYjNJd0NnWUlLb1pJemowRUF3SURTQUF3UlFJaEFOVFFaVGxvdCtQSGk5a2NzbHl1ZHdqSXFaNTdVbms2VXdwVHJ4Wm40bXQxQWlBd3poaW5jUHNvSE5FWnIrdEFFZmtOb0crMzVGVG9jbElxV0F4aVErMnpNdz09IiwiTUlJQ2lqQ0NBaStnQXdJQkFnSVVRK0dadDY5MzQzKzhqRENNZmxVSUc0SWwyTXN3Q2dZSUtvWkl6ajBFQXdJd2daa3hDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RVdNQlFHQTFVRUF3d05WbUZ3YjNJZ1VtOXZkQ0JEUVRFbU1DUUdDU3FHU0liM0RRRUpBUllYWVdSdGFXNUFkbUZ3YjNJdVpYaGhiWEJzWlM1amIyMHdIaGNOTWpVd01URXdNRGt5TnpFNFdoY05NelV3TVRBNE1Ea3lOekU0V2pDQm1URUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdNQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIREFoT1pYY2dXVzl5YXpFT01Bd0dBMVVFQ2d3RlZtRndiM0l4RkRBU0JnTlZCQXNNQzBWdVoybHVaV1Z5YVc1bk1SWXdGQVlEVlFRRERBMVdZWEJ2Y2lCU2IyOTBJRU5CTVNZd0pBWUpLb1pJaHZjTkFRa0JGaGRoWkcxcGJrQjJZWEJ2Y2k1bGVHRnRjR3hsTG1OdmJUQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJLXC83NHVWeG85YlZwYkYxM2wzZGg3dHhVSDIwRnBPd1c3SnNOdlc2eUd6UnJKcjBKY0dJVUpGVW1sOGhvcmdcL21aTFFxZGUrTFRLZjRWQnlXbGs3aEJLalV6QlJNQjBHQTFVZERnUVdCQlR3b3g1VEs4eXI3WkRKY2lldUVvNmhPVUp2Y2pBZkJnTlZIU01FR0RBV2dCVHdveDVUSzh5cjdaREpjaWV1RW82aE9VSnZjakFQQmdOVkhSTUJBZjhFQlRBREFRSFwvTUFvR0NDcUdTTTQ5QkFNQ0Ewa0FNRVlDSVFEREIzcysyQ1VsXC9Zclh4UVVieWwzOEdOU3BYY29nWWZFY1dYRVFtUXRPbGdJaEFKSHplN0NDVERIT0R0R2FuODlyMlZFRDd0WHB3R2tcLzVFV0xhclR2b2hJMyJdLCJ0eXAiOiJKV1QifQ.eyJjb29sIjpmYWxzZX0.eIuHbLhYHV7Qld2rqmjFzzKKxJuk5FemIYQDAYDe-WjzL_qdSjP4qBbDq81j6Qi9u_-bK4KJNpH1fm8hmCoMOA
    """
let validToken = """
    eyJhbGciOiJFUzI1NiIsIng1YyI6WyJNSUlDZmpDQ0FpT2dBd0lCQWdJVUZ5b29aUm1zXC9TUzVKdllMMGRsNmhId1I1bFl3Q2dZSUtvWkl6ajBFQXdJd2dhRXhDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RWVNQndHQTFVRUF3d1ZWbUZ3YjNJZ1NXNTBaWEp0WldScFlYUmxJRU5CTVNZd0pBWUpLb1pJaHZjTkFRa0JGaGRoWkcxcGJrQjJZWEJ2Y2k1bGVHRnRjR3hsTG1OdmJUQWVGdzB5TlRBeE1UQXdPVEkzTVRoYUZ3MHlOakF4TVRBd09USTNNVGhhTUlHV01Rc3dDUVlEVlFRR0V3SlZVekVSTUE4R0ExVUVDQXdJVG1WM0lGbHZjbXN4RVRBUEJnTlZCQWNNQ0U1bGR5QlpiM0pyTVE0d0RBWURWUVFLREFWV1lYQnZjakVVTUJJR0ExVUVDd3dMUlc1bmFXNWxaWEpwYm1jeEV6QVJCZ05WQkFNTUNsWmhjRzl5SUV4bFlXWXhKakFrQmdrcWhraUc5dzBCQ1FFV0YyRmtiV2x1UUhaaGNHOXlMbVY0WVcxd2JHVXVZMjl0TUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFWExLUHNkMVBpczE4Wno3NzlMSTNqZTRHQ1wvR0xlZUp4eFM3VjVud0Z4U0F0U3htSlhaUGx3RDZjZEZydVhkd0p2ekpuT1ByWFdENHBZdkFNUFwvN0NTNk5DTUVBd0hRWURWUjBPQkJZRUZIXC9ja0Z0bWtKYll5aXZ5VmtvdHAyRklwTnFXTUI4R0ExVWRJd1FZTUJhQUZIUFd6am43SHhHSTJ4SHhSTkVKaHkzU1JJZVZNQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUURSd1g4TTZEVEgwSmVjZGNSdDBYVTdXUlhXZkZvRUZmbGRrTFJKOVU0dlFRSWhBTHBWUFhVSVozTEx2MVVTYlk3M0pRNWNrMEk3OTJjdTVcL25hQ2VUNm84ckgiLCJNSUlDampDQ0FqU2dBd0lCQWdJVVM1Uk1IUVNQOTFFWkhaRzlHTG1LcFNcL0NxYm93Q2dZSUtvWkl6ajBFQXdJd2daa3hDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RVdNQlFHQTFVRUF3d05WbUZ3YjNJZ1VtOXZkQ0JEUVRFbU1DUUdDU3FHU0liM0RRRUpBUllYWVdSdGFXNUFkbUZ3YjNJdVpYaGhiWEJzWlM1amIyMHdIaGNOTWpVd01URXdNRGt5TnpFNFdoY05NekF3TVRBNU1Ea3lOekU0V2pDQm9URUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdNQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIREFoT1pYY2dXVzl5YXpFT01Bd0dBMVVFQ2d3RlZtRndiM0l4RkRBU0JnTlZCQXNNQzBWdVoybHVaV1Z5YVc1bk1SNHdIQVlEVlFRRERCVldZWEJ2Y2lCSmJuUmxjbTFsWkdsaGRHVWdRMEV4SmpBa0Jna3Foa2lHOXcwQkNRRVdGMkZrYldsdVFIWmhjRzl5TG1WNFlXMXdiR1V1WTI5dE1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRXR2c1JaTmFvWXhlME9FY3lTcDRQanQxWjF4NmJ2VVwvYU5PVVdjazVpZEJpWHpMZnExYXREaGpsNVpSUEFOSWozeXI3aGw0clNrZ3FramFiQXJLY250S05RTUU0d0RBWURWUjBUQkFVd0F3RUJcL3pBZEJnTlZIUTRFRmdRVWM5Yk9PZnNmRVlqYkVmRkUwUW1ITGRKRWg1VXdId1lEVlIwakJCZ3dGb0FVOEtNZVV5dk1xKzJReVhJbnJoS09vVGxDYjNJd0NnWUlLb1pJemowRUF3SURTQUF3UlFJaEFOVFFaVGxvdCtQSGk5a2NzbHl1ZHdqSXFaNTdVbms2VXdwVHJ4Wm40bXQxQWlBd3poaW5jUHNvSE5FWnIrdEFFZmtOb0crMzVGVG9jbElxV0F4aVErMnpNdz09IiwiTUlJQ2lqQ0NBaStnQXdJQkFnSVVRK0dadDY5MzQzKzhqRENNZmxVSUc0SWwyTXN3Q2dZSUtvWkl6ajBFQXdJd2daa3hDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RVdNQlFHQTFVRUF3d05WbUZ3YjNJZ1VtOXZkQ0JEUVRFbU1DUUdDU3FHU0liM0RRRUpBUllYWVdSdGFXNUFkbUZ3YjNJdVpYaGhiWEJzWlM1amIyMHdIaGNOTWpVd01URXdNRGt5TnpFNFdoY05NelV3TVRBNE1Ea3lOekU0V2pDQm1URUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdNQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIREFoT1pYY2dXVzl5YXpFT01Bd0dBMVVFQ2d3RlZtRndiM0l4RkRBU0JnTlZCQXNNQzBWdVoybHVaV1Z5YVc1bk1SWXdGQVlEVlFRRERBMVdZWEJ2Y2lCU2IyOTBJRU5CTVNZd0pBWUpLb1pJaHZjTkFRa0JGaGRoWkcxcGJrQjJZWEJ2Y2k1bGVHRnRjR3hsTG1OdmJUQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJLXC83NHVWeG85YlZwYkYxM2wzZGg3dHhVSDIwRnBPd1c3SnNOdlc2eUd6UnJKcjBKY0dJVUpGVW1sOGhvcmdcL21aTFFxZGUrTFRLZjRWQnlXbGs3aEJLalV6QlJNQjBHQTFVZERnUVdCQlR3b3g1VEs4eXI3WkRKY2lldUVvNmhPVUp2Y2pBZkJnTlZIU01FR0RBV2dCVHdveDVUSzh5cjdaREpjaWV1RW82aE9VSnZjakFQQmdOVkhSTUJBZjhFQlRBREFRSFwvTUFvR0NDcUdTTTQ5QkFNQ0Ewa0FNRVlDSVFEREIzcysyQ1VsXC9Zclh4UVVieWwzOEdOU3BYY29nWWZFY1dYRVFtUXRPbGdJaEFKSHplN0NDVERIT0R0R2FuODlyMlZFRDd0WHB3R2tcLzVFV0xhclR2b2hJMyJdLCJ0eXAiOiJKV1QifQ.eyJjb29sIjp0cnVlfQ.RzvCDMflF974cTCZmUkImLxYJHMTmfnCShCmvf-B38Bc4sL3POrTY-YPCDq7_ENudUKJP9WDQ-6Gn1PcjmXfaQ
    """
let missingLeafAndIntermediateToken = """
    eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlDaWpDQ0FpK2dBd0lCQWdJVVErR1p0NjkzNDMrOGpEQ01mbFVJRzRJbDJNc3dDZ1lJS29aSXpqMEVBd0l3Z1preEN6QUpCZ05WQkFZVEFsVlRNUkV3RHdZRFZRUUlEQWhPWlhjZ1dXOXlhekVSTUE4R0ExVUVCd3dJVG1WM0lGbHZjbXN4RGpBTUJnTlZCQW9NQlZaaGNHOXlNUlF3RWdZRFZRUUxEQXRGYm1kcGJtVmxjbWx1WnpFV01CUUdBMVVFQXd3TlZtRndiM0lnVW05dmRDQkRRVEVtTUNRR0NTcUdTSWIzRFFFSkFSWVhZV1J0YVc1QWRtRndiM0l1WlhoaGJYQnNaUzVqYjIwd0hoY05NalV3TVRFd01Ea3lOekU0V2hjTk16VXdNVEE0TURreU56RTRXakNCbVRFTE1Ba0dBMVVFQmhNQ1ZWTXhFVEFQQmdOVkJBZ01DRTVsZHlCWmIzSnJNUkV3RHdZRFZRUUhEQWhPWlhjZ1dXOXlhekVPTUF3R0ExVUVDZ3dGVm1Gd2IzSXhGREFTQmdOVkJBc01DMFZ1WjJsdVpXVnlhVzVuTVJZd0ZBWURWUVFEREExV1lYQnZjaUJTYjI5MElFTkJNU1l3SkFZSktvWklodmNOQVFrQkZoZGhaRzFwYmtCMllYQnZjaTVsZUdGdGNHeGxMbU52YlRCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQktcLzc0dVZ4bzliVnBiRjEzbDNkaDd0eFVIMjBGcE93VzdKc052VzZ5R3pSckpyMEpjR0lVSkZVbWw4aG9yZ1wvbVpMUXFkZStMVEtmNFZCeVdsazdoQktqVXpCUk1CMEdBMVVkRGdRV0JCVHdveDVUSzh5cjdaREpjaWV1RW82aE9VSnZjakFmQmdOVkhTTUVHREFXZ0JUd294NVRLOHlyN1pESmNpZXVFbzZoT1VKdmNqQVBCZ05WSFJNQkFmOEVCVEFEQVFIXC9NQW9HQ0NxR1NNNDlCQU1DQTBrQU1FWUNJUUREQjNzKzJDVWxcL1lyWHhRVWJ5bDM4R05TcFhjb2dZZkVjV1hFUW1RdE9sZ0loQUpIemU3Q0NUREhPRHRHYW44OXIyVkVEN3RYcHdHa1wvNUVXTGFyVHZvaEkzIl19.eyJjb29sIjp0cnVlfQ.KlLuKx9RedV8Ibg5mYYrGdHX-dYZv4z3qpo-j3nejdM9NFl8cN-fSp-jZcDgdVpf6whYNiqrkS0LJYvmD47Ylg
    """
let missingLeafToken = """
    eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlDampDQ0FqU2dBd0lCQWdJVVM1Uk1IUVNQOTFFWkhaRzlHTG1LcFNcL0NxYm93Q2dZSUtvWkl6ajBFQXdJd2daa3hDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RVdNQlFHQTFVRUF3d05WbUZ3YjNJZ1VtOXZkQ0JEUVRFbU1DUUdDU3FHU0liM0RRRUpBUllYWVdSdGFXNUFkbUZ3YjNJdVpYaGhiWEJzWlM1amIyMHdIaGNOTWpVd01URXdNRGt5TnpFNFdoY05NekF3TVRBNU1Ea3lOekU0V2pDQm9URUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdNQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIREFoT1pYY2dXVzl5YXpFT01Bd0dBMVVFQ2d3RlZtRndiM0l4RkRBU0JnTlZCQXNNQzBWdVoybHVaV1Z5YVc1bk1SNHdIQVlEVlFRRERCVldZWEJ2Y2lCSmJuUmxjbTFsWkdsaGRHVWdRMEV4SmpBa0Jna3Foa2lHOXcwQkNRRVdGMkZrYldsdVFIWmhjRzl5TG1WNFlXMXdiR1V1WTI5dE1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRXR2c1JaTmFvWXhlME9FY3lTcDRQanQxWjF4NmJ2VVwvYU5PVVdjazVpZEJpWHpMZnExYXREaGpsNVpSUEFOSWozeXI3aGw0clNrZ3FramFiQXJLY250S05RTUU0d0RBWURWUjBUQkFVd0F3RUJcL3pBZEJnTlZIUTRFRmdRVWM5Yk9PZnNmRVlqYkVmRkUwUW1ITGRKRWg1VXdId1lEVlIwakJCZ3dGb0FVOEtNZVV5dk1xKzJReVhJbnJoS09vVGxDYjNJd0NnWUlLb1pJemowRUF3SURTQUF3UlFJaEFOVFFaVGxvdCtQSGk5a2NzbHl1ZHdqSXFaNTdVbms2VXdwVHJ4Wm40bXQxQWlBd3poaW5jUHNvSE5FWnIrdEFFZmtOb0crMzVGVG9jbElxV0F4aVErMnpNdz09IiwiTUlJQ2lqQ0NBaStnQXdJQkFnSVVRK0dadDY5MzQzKzhqRENNZmxVSUc0SWwyTXN3Q2dZSUtvWkl6ajBFQXdJd2daa3hDekFKQmdOVkJBWVRBbFZUTVJFd0R3WURWUVFJREFoT1pYY2dXVzl5YXpFUk1BOEdBMVVFQnd3SVRtVjNJRmx2Y21zeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJRd0VnWURWUVFMREF0RmJtZHBibVZsY21sdVp6RVdNQlFHQTFVRUF3d05WbUZ3YjNJZ1VtOXZkQ0JEUVRFbU1DUUdDU3FHU0liM0RRRUpBUllYWVdSdGFXNUFkbUZ3YjNJdVpYaGhiWEJzWlM1amIyMHdIaGNOTWpVd01URXdNRGt5TnpFNFdoY05NelV3TVRBNE1Ea3lOekU0V2pDQm1URUxNQWtHQTFVRUJoTUNWVk14RVRBUEJnTlZCQWdNQ0U1bGR5QlpiM0pyTVJFd0R3WURWUVFIREFoT1pYY2dXVzl5YXpFT01Bd0dBMVVFQ2d3RlZtRndiM0l4RkRBU0JnTlZCQXNNQzBWdVoybHVaV1Z5YVc1bk1SWXdGQVlEVlFRRERBMVdZWEJ2Y2lCU2IyOTBJRU5CTVNZd0pBWUpLb1pJaHZjTkFRa0JGaGRoWkcxcGJrQjJZWEJ2Y2k1bGVHRnRjR3hsTG1OdmJUQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJLXC83NHVWeG85YlZwYkYxM2wzZGg3dHhVSDIwRnBPd1c3SnNOdlc2eUd6UnJKcjBKY0dJVUpGVW1sOGhvcmdcL21aTFFxZGUrTFRLZjRWQnlXbGs3aEJLalV6QlJNQjBHQTFVZERnUVdCQlR3b3g1VEs4eXI3WkRKY2lldUVvNmhPVUp2Y2pBZkJnTlZIU01FR0RBV2dCVHdveDVUSzh5cjdaREpjaWV1RW82aE9VSnZjakFQQmdOVkhSTUJBZjhFQlRBREFRSFwvTUFvR0NDcUdTTTQ5QkFNQ0Ewa0FNRVlDSVFEREIzcysyQ1VsXC9Zclh4UVVieWwzOEdOU3BYY29nWWZFY1dYRVFtUXRPbGdJaEFKSHplN0NDVERIT0R0R2FuODlyMlZFRDd0WHB3R2tcLzVFV0xhclR2b2hJMyJdfQ.eyJjb29sIjp0cnVlfQ.lJjtp19LB206fFuPr7qqHw4wdLNLeBa9gh0Z5_MvUEwhAJNm-XyRtbr8ahoo-ft5iE7VKAq4X658RpM_4p6xlg
    """
let expiredLeafToken = """
    eyJ4NWMiOlsiTUlJQ2hUQ0NBaXVnQXdJQkFnSVVGeW9vWlJtc1wvU1M1SnZZTDBkbDZoSHdSNWxjd0NnWUlLb1pJemowRUF3SXdnYUV4Q3pBSkJnTlZCQVlUQWxWVE1SRXdEd1lEVlFRSURBaE9aWGNnV1c5eWF6RVJNQThHQTFVRUJ3d0lUbVYzSUZsdmNtc3hEakFNQmdOVkJBb01CVlpoY0c5eU1SUXdFZ1lEVlFRTERBdEZibWRwYm1WbGNtbHVaekVlTUJ3R0ExVUVBd3dWVm1Gd2IzSWdTVzUwWlhKdFpXUnBZWFJsSUVOQk1TWXdKQVlKS29aSWh2Y05BUWtCRmhkaFpHMXBia0IyWVhCdmNpNWxlR0Z0Y0d4bExtTnZiVEFlRncweU1EQXhNREV3TVRBd01EQmFGdzB5TURBeE1ESXdNVEF3TURCYU1JR2VNUXN3Q1FZRFZRUUdFd0pWVXpFUk1BOEdBMVVFQ0F3SVRtVjNJRmx2Y21zeEVUQVBCZ05WQkFjTUNFNWxkeUJaYjNKck1RNHdEQVlEVlFRS0RBVldZWEJ2Y2pFVU1CSUdBMVVFQ3d3TFJXNW5hVzVsWlhKcGJtY3hHekFaQmdOVkJBTU1FbFpoY0c5eUlFVjRjR2x5WldRZ1RHVmhaakVtTUNRR0NTcUdTSWIzRFFFSkFSWVhZV1J0YVc1QWRtRndiM0l1WlhoaGJYQnNaUzVqYjIwd1dUQVRCZ2NxaGtqT1BRSUJCZ2dxaGtqT1BRTUJCd05DQUFRUHZqNDE0U0JTeGM5QzVrZDdoaWlXYkhCXC9CMVozKzBjWFAyeVRYMU1LdFN0XC9reDBJQ3gyUTdFTW1oNU9NMU1JUmZCRTU0Y3FwUjgrbUhrNVNEUWlybzBJd1FEQWRCZ05WSFE0RUZnUVVtQVU0VzVBXC9qcnlTc2d3NEVwbUYxRFIwRnc4d0h3WURWUjBqQkJnd0ZvQVVjOWJPT2ZzZkVZamJFZkZFMFFtSExkSkVoNVV3Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUlnRzd2YzV5U1ZlcW50R0xucnlDWDJlcW40XC91NlJKRFpTa01jVFI3UHBCODRDSVFDVkhwSk90RndxOVc1WCtEUm5aUFplOGxqeUJPcm15TllodmRER2k1RTVoUT09IiwiTUlJQ2pqQ0NBalNnQXdJQkFnSVVTNVJNSFFTUDkxRVpIWkc5R0xtS3BTXC9DcWJvd0NnWUlLb1pJemowRUF3SXdnWmt4Q3pBSkJnTlZCQVlUQWxWVE1SRXdEd1lEVlFRSURBaE9aWGNnV1c5eWF6RVJNQThHQTFVRUJ3d0lUbVYzSUZsdmNtc3hEakFNQmdOVkJBb01CVlpoY0c5eU1SUXdFZ1lEVlFRTERBdEZibWRwYm1WbGNtbHVaekVXTUJRR0ExVUVBd3dOVm1Gd2IzSWdVbTl2ZENCRFFURW1NQ1FHQ1NxR1NJYjNEUUVKQVJZWFlXUnRhVzVBZG1Gd2IzSXVaWGhoYlhCc1pTNWpiMjB3SGhjTk1qVXdNVEV3TURreU56RTRXaGNOTXpBd01UQTVNRGt5TnpFNFdqQ0JvVEVMTUFrR0ExVUVCaE1DVlZNeEVUQVBCZ05WQkFnTUNFNWxkeUJaYjNKck1SRXdEd1lEVlFRSERBaE9aWGNnV1c5eWF6RU9NQXdHQTFVRUNnd0ZWbUZ3YjNJeEZEQVNCZ05WQkFzTUMwVnVaMmx1WldWeWFXNW5NUjR3SEFZRFZRUUREQlZXWVhCdmNpQkpiblJsY20xbFpHbGhkR1VnUTBFeEpqQWtCZ2txaGtpRzl3MEJDUUVXRjJGa2JXbHVRSFpoY0c5eUxtVjRZVzF3YkdVdVkyOXRNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUV0dnNSWk5hb1l4ZTBPRWN5U3A0UGp0MVoxeDZidlVcL2FOT1VXY2s1aWRCaVh6TGZxMWF0RGhqbDVaUlBBTklqM3lyN2hsNHJTa2dxa2phYkFyS2NudEtOUU1FNHdEQVlEVlIwVEJBVXdBd0VCXC96QWRCZ05WSFE0RUZnUVVjOWJPT2ZzZkVZamJFZkZFMFFtSExkSkVoNVV3SHdZRFZSMGpCQmd3Rm9BVThLTWVVeXZNcSsyUXlYSW5yaEtPb1RsQ2IzSXdDZ1lJS29aSXpqMEVBd0lEU0FBd1JRSWhBTlRRWlRsb3QrUEhpOWtjc2x5dWR3aklxWjU3VW5rNlV3cFRyeFpuNG10MUFpQXd6aGluY1Bzb0hORVpyK3RBRWZrTm9HKzM1RlRvY2xJcVdBeGlRKzJ6TXc9PSIsIk1JSUNpakNDQWkrZ0F3SUJBZ0lVUStHWnQ2OTM0Mys4akRDTWZsVUlHNElsMk1zd0NnWUlLb1pJemowRUF3SXdnWmt4Q3pBSkJnTlZCQVlUQWxWVE1SRXdEd1lEVlFRSURBaE9aWGNnV1c5eWF6RVJNQThHQTFVRUJ3d0lUbVYzSUZsdmNtc3hEakFNQmdOVkJBb01CVlpoY0c5eU1SUXdFZ1lEVlFRTERBdEZibWRwYm1WbGNtbHVaekVXTUJRR0ExVUVBd3dOVm1Gd2IzSWdVbTl2ZENCRFFURW1NQ1FHQ1NxR1NJYjNEUUVKQVJZWFlXUnRhVzVBZG1Gd2IzSXVaWGhoYlhCc1pTNWpiMjB3SGhjTk1qVXdNVEV3TURreU56RTRXaGNOTXpVd01UQTRNRGt5TnpFNFdqQ0JtVEVMTUFrR0ExVUVCaE1DVlZNeEVUQVBCZ05WQkFnTUNFNWxkeUJaYjNKck1SRXdEd1lEVlFRSERBaE9aWGNnV1c5eWF6RU9NQXdHQTFVRUNnd0ZWbUZ3YjNJeEZEQVNCZ05WQkFzTUMwVnVaMmx1WldWeWFXNW5NUll3RkFZRFZRUUREQTFXWVhCdmNpQlNiMjkwSUVOQk1TWXdKQVlKS29aSWh2Y05BUWtCRmhkaFpHMXBia0IyWVhCdmNpNWxlR0Z0Y0d4bExtTnZiVEJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCS1wvNzR1VnhvOWJWcGJGMTNsM2RoN3R4VUgyMEZwT3dXN0pzTnZXNnlHelJySnIwSmNHSVVKRlVtbDhob3JnXC9tWkxRcWRlK0xUS2Y0VkJ5V2xrN2hCS2pVekJSTUIwR0ExVWREZ1FXQkJUd294NVRLOHlyN1pESmNpZXVFbzZoT1VKdmNqQWZCZ05WSFNNRUdEQVdnQlR3b3g1VEs4eXI3WkRKY2lldUVvNmhPVUp2Y2pBUEJnTlZIUk1CQWY4RUJUQURBUUhcL01Bb0dDQ3FHU000OUJBTUNBMGtBTUVZQ0lRRERCM3MrMkNVbFwvWXJYeFFVYnlsMzhHTlNwWGNvZ1lmRWNXWEVRbVF0T2xnSWhBSkh6ZTdDQ1RESE9EdEdhbjg5cjJWRUQ3dFhwd0drXC81RVdMYXJUdm9oSTMiXSwidHlwIjoiSldUIiwiYWxnIjoiRVMyNTYifQ.eyJjb29sIjp0cnVlfQ.eUvON3ZYRJmn9P1RC8fT5c5rIshYc3TjarR14V9Q9o3D-YALZ6chfu_Z20btJaUN61X_cFoYYLRJY4eIFu7geA
    """
let missingIntermediateAndRootToken = """
    eyJ4NWMiOlsiTUlJQ2ZqQ0NBaU9nQXdJQkFnSVVGeW9vWlJtc1wvU1M1SnZZTDBkbDZoSHdSNWxZd0NnWUlLb1pJemowRUF3SXdnYUV4Q3pBSkJnTlZCQVlUQWxWVE1SRXdEd1lEVlFRSURBaE9aWGNnV1c5eWF6RVJNQThHQTFVRUJ3d0lUbVYzSUZsdmNtc3hEakFNQmdOVkJBb01CVlpoY0c5eU1SUXdFZ1lEVlFRTERBdEZibWRwYm1WbGNtbHVaekVlTUJ3R0ExVUVBd3dWVm1Gd2IzSWdTVzUwWlhKdFpXUnBZWFJsSUVOQk1TWXdKQVlKS29aSWh2Y05BUWtCRmhkaFpHMXBia0IyWVhCdmNpNWxlR0Z0Y0d4bExtTnZiVEFlRncweU5UQXhNVEF3T1RJM01UaGFGdzB5TmpBeE1UQXdPVEkzTVRoYU1JR1dNUXN3Q1FZRFZRUUdFd0pWVXpFUk1BOEdBMVVFQ0F3SVRtVjNJRmx2Y21zeEVUQVBCZ05WQkFjTUNFNWxkeUJaYjNKck1RNHdEQVlEVlFRS0RBVldZWEJ2Y2pFVU1CSUdBMVVFQ3d3TFJXNW5hVzVsWlhKcGJtY3hFekFSQmdOVkJBTU1DbFpoY0c5eUlFeGxZV1l4SmpBa0Jna3Foa2lHOXcwQkNRRVdGMkZrYldsdVFIWmhjRzl5TG1WNFlXMXdiR1V1WTI5dE1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRVhMS1BzZDFQaXMxOFp6Nzc5TEkzamU0R0NcL0dMZWVKeHhTN1Y1bndGeFNBdFN4bUpYWlBsd0Q2Y2RGcnVYZHdKdnpKbk9QclhXRDRwWXZBTVBcLzdDUzZOQ01FQXdIUVlEVlIwT0JCWUVGSFwvY2tGdG1rSmJZeWl2eVZrb3RwMkZJcE5xV01COEdBMVVkSXdRWU1CYUFGSFBXempuN0h4R0kyeEh4Uk5FSmh5M1NSSWVWTUFvR0NDcUdTTTQ5QkFNQ0Ewa0FNRVlDSVFEUndYOE02RFRIMEplY2RjUnQwWFU3V1JYV2ZGb0VGZmxka0xSSjlVNHZRUUloQUxwVlBYVUlaM0xMdjFVU2JZNzNKUTVjazBJNzkyY3U1XC9uYUNlVDZvOHJIIl0sImFsZyI6IkVTMjU2IiwidHlwIjoiSldUIn0.eyJjb29sIjp0cnVlfQ.PhxN-7AYea0WzTTL8GcBoVk48csux9oEvodMSuDbA4Ayxv1fO9rH-vwtSP7OO66F2DjPYUBKp5GGvTC4MA0R0g
    """

let x5cCerts = [
    """
    -----BEGIN CERTIFICATE-----
    MIICfTCCAiOgAwIBAgIUdSjHMW4Ee5DUpcOyHQx3KOEEoHwwCgYIKoZIzj0EAwIw
    gaExCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhOZXcgWW9yazERMA8GA1UEBwwITmV3
    IFlvcmsxDjAMBgNVBAoMBVZhcG9yMRQwEgYDVQQLDAtFbmdpbmVlcmluZzEeMBwG
    A1UEAwwVVmFwb3IgSW50ZXJtZWRpYXRlIENBMSYwJAYJKoZIhvcNAQkBFhdhZG1p
    bkB2YXBvci5leGFtcGxlLmNvbTAeFw0yNTAxMTAwOTQxNDJaFw0yNjAxMTAwOTQx
    NDJaMIGWMQswCQYDVQQGEwJVUzERMA8GA1UECAwITmV3IFlvcmsxETAPBgNVBAcM
    CE5ldyBZb3JrMQ4wDAYDVQQKDAVWYXBvcjEUMBIGA1UECwwLRW5naW5lZXJpbmcx
    EzARBgNVBAMMClZhcG9yIExlYWYxJjAkBgkqhkiG9w0BCQEWF2FkbWluQHZhcG9y
    LmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEe6mlYhBYd3VM
    +yMXmW0ZwsJCzfUWU7RWUdkI35FyMcY/BQLMM2RFrrgyX8CuEVJsT6Bgzgg+hyDh
    YMKwtMX1i6NCMEAwHQYDVR0OBBYEFEbhwCoMFqviogGLUVJrHgLiAMlAMB8GA1Ud
    IwQYMBaAFF0UJCCJyb67oh5/1bbXdwB/nKKnMAoGCCqGSM49BAMCA0gAMEUCIAQZ
    sKPKXPX1tD+rGyYQQu7Knedq1uZz8Vtoun7zx+kPAiEAv/HympBtgony5zIb3Wme
    EAOpDqw6rP+TeYWgk0XyaJA=
    -----END CERTIFICATE-----
    """,
    """
    -----BEGIN CERTIFICATE-----
    MIICjjCCAjSgAwIBAgIULepBF8dIlNcyWDaMBGr29YX0bD4wCgYIKoZIzj0EAwIw
    gZkxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhOZXcgWW9yazERMA8GA1UEBwwITmV3
    IFlvcmsxDjAMBgNVBAoMBVZhcG9yMRQwEgYDVQQLDAtFbmdpbmVlcmluZzEWMBQG
    A1UEAwwNVmFwb3IgUm9vdCBDQTEmMCQGCSqGSIb3DQEJARYXYWRtaW5AdmFwb3Iu
    ZXhhbXBsZS5jb20wHhcNMjUwMTEwMDk0MTQyWhcNMzAwMTA5MDk0MTQyWjCBoTEL
    MAkGA1UEBhMCVVMxETAPBgNVBAgMCE5ldyBZb3JrMREwDwYDVQQHDAhOZXcgWW9y
    azEOMAwGA1UECgwFVmFwb3IxFDASBgNVBAsMC0VuZ2luZWVyaW5nMR4wHAYDVQQD
    DBVWYXBvciBJbnRlcm1lZGlhdGUgQ0ExJjAkBgkqhkiG9w0BCQEWF2FkbWluQHZh
    cG9yLmV4YW1wbGUuY29tMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEb+p+OAnz
    3W63DLze82XsWLqI75MJi6GGTdnnW9HtQhxDCMBiNkFHpUu6qtsaIEsm0PCiW640
    fLEf0hG+CmNfQaNQME4wDAYDVR0TBAUwAwEB/zAdBgNVHQ4EFgQUXRQkIInJvrui
    Hn/Vttd3AH+coqcwHwYDVR0jBBgwFoAUe3e998Fah3ndWj04w7r5VK9zhiAwCgYI
    KoZIzj0EAwIDSAAwRQIhAO6Xr51C3jLaEN+gMWm0eeeK6cQFn2xIy/F8Se0jAyAo
    AiAeSRkjHbrgK63cbza6Qz5ClaHYwg6WF/VNMglE10CDGw==
    -----END CERTIFICATE-----
    """,
    """
    -----BEGIN CERTIFICATE-----
    MIICiTCCAi+gAwIBAgIUcD7x8o9UAoMCY58OG6cNm0jqTJ0wCgYIKoZIzj0EAwIw
    gZkxCzAJBgNVBAYTAlVTMREwDwYDVQQIDAhOZXcgWW9yazERMA8GA1UEBwwITmV3
    IFlvcmsxDjAMBgNVBAoMBVZhcG9yMRQwEgYDVQQLDAtFbmdpbmVlcmluZzEWMBQG
    A1UEAwwNVmFwb3IgUm9vdCBDQTEmMCQGCSqGSIb3DQEJARYXYWRtaW5AdmFwb3Iu
    ZXhhbXBsZS5jb20wHhcNMjUwMTEwMDk0MTQyWhcNMzUwMTA4MDk0MTQyWjCBmTEL
    MAkGA1UEBhMCVVMxETAPBgNVBAgMCE5ldyBZb3JrMREwDwYDVQQHDAhOZXcgWW9y
    azEOMAwGA1UECgwFVmFwb3IxFDASBgNVBAsMC0VuZ2luZWVyaW5nMRYwFAYDVQQD
    DA1WYXBvciBSb290IENBMSYwJAYJKoZIhvcNAQkBFhdhZG1pbkB2YXBvci5leGFt
    cGxlLmNvbTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABFUHLLDNUDFdH2TGjqHj
    NKjvCsClKYEoWbmMXoypA6P2KHmWVVC3VSQ0hWVrpN8jza/tsLe03fjvfYrsf7IN
    yLmjUzBRMB0GA1UdDgQWBBR7d733wVqHed1aPTjDuvlUr3OGIDAfBgNVHSMEGDAW
    gBR7d733wVqHed1aPTjDuvlUr3OGIDAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49
    BAMCA0gAMEUCIEwkrw2Jx6BbuYnZb3LQ6I3hZZnjHA5Co4Re1IKf3sRBAiEAugsW
    oXB0T7ftyoxbWj5qDUSnTPN+P27kWOf1GceWh3U=
    -----END CERTIFICATE-----
    """,
]

let x5cLeafCertKey = """
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEIJuYkleZWC5RrZUnepPFx25QI5msgOROv/KV97lknYzsoAoGCCqGSM49
    AwEHoUQDQgAEe6mlYhBYd3VM+yMXmW0ZwsJCzfUWU7RWUdkI35FyMcY/BQLMM2RF
    rrgyX8CuEVJsT6Bgzgg+hyDhYMKwtMX1iw==
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
