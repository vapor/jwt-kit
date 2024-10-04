import JWTKit
import Testing
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
@Suite("X5CTests")
struct X5CTests {
    let verifier = try! X5CVerifier(rootCertificates: [
        // Trusted root:
        """
        -----BEGIN CERTIFICATE-----
        MIIB4TCCAYegAwIBAgIUDoOefefCNq/TGWriIsYHvz0LpNIwCgYIKoZIzj0EAwIw
        RjELMAkGA1UEBhMCVVMxEzARBgNVBAgMClNvbWUtU3RhdGUxDjAMBgNVBAoMBVZh
        cG9yMRIwEAYDVQQDDAlyb290LWNlcnQwHhcNMjMxMDI0MTIwODI3WhcNMzMxMDIx
        MTIwODI3WjBGMQswCQYDVQQGEwJVUzETMBEGA1UECAwKU29tZS1TdGF0ZTEOMAwG
        A1UECgwFVmFwb3IxEjAQBgNVBAMMCXJvb3QtY2VydDBZMBMGByqGSM49AgEGCCqG
        SM49AwEHA0IABNpv+HG52jOT1W+r1k13bJo2k9DyRyFbycBpPsWQKft9nxwEHvzD
        j1ivoMfajxlL+n/FLBnOnY63mFWmzaoZvH+jUzBRMB0GA1UdDgQWBBRjXfPURcaf
        1QF+mCl9T21Bu8xFCDAfBgNVHSMEGDAWgBRjXfPURcaf1QF+mCl9T21Bu8xFCDAP
        BgNVHRMBAf8EBTADAQH/MAoGCCqGSM49BAMCA0gAMEUCIGIpX9lliU135V8+LY6/
        cjBmGrKKNlYWLLoZ6DiauzdJAiEA9GSAIGhfM9kbWlkcjMs6lA4pwf4RfUEFeghY
        pZKbqFo=
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
            })

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
            })

        switch result {
        case .couldNotValidate:
            break
        case .validCertificate:
            Issue.record("Should not have validated")
        }
    }

    @Test("Test signing with x5c chain")
    func signWithX5CChain() async throws {
        let keyCollection = try await JWTKeyCollection().add(
            ecdsa: ES256PrivateKey(pem: x5cLeafCertKey))

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
        let keyCollection = try await JWTKeyCollection().add(
            ecdsa: ES256PrivateKey(pem: x5cLeafCertKey))

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
            let prefixIndex = encoded.index(encoded.startIndex, offsetBy: 64, limitedBy: encoded.endIndex) ?? encoded.endIndex
            pemLines.append(encoded[..<prefixIndex])
            encoded = encoded[prefixIndex...]
        }

        pemLines.append("-----END CERTIFICATE-----")

        return pemLines.joined(separator: "\n")
    }
}

let validToken = """
    eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlCanpDQ0FUVUNGSDhFWFBJbDBRbDQwYzdKOEhkK2R6QWgwY3dVTUFvR0NDcUdTTTQ5QkFNQ01FNHhDekFKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFJREFwVGIyMWxMVk4wWVhSbE1RNHdEQVlEVlFRS0RBVldZWEJ2Y2pFYU1CZ0dBMVVFQXd3UmFXNTBaWEp0WldScFlYUmxMV05sY25Rd0hoY05Nak14TURJME1UTTBNalU1V2hjTk1qUXhNREl6TVRNME1qVTVXakJHTVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNBd0tVMjl0WlMxVGRHRjBaVEVPTUF3R0ExVUVDZ3dGVm1Gd2IzSXhFakFRQmdOVkJBTU1DV3hsWVdZdFkyVnlkREJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCRU85VjZLQWhSR0l4QWx2Ukl6U3BtSVRmVVZiWHl5ZGMvZWdlbHpLLzZ3NDEySmc4RDJlSVRkOHVDRmxnVmh4WUlkR1pNN1hYUWhaNmhOZnE2S3JyUG93Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUxJaXhudE93V3o4NlFHa0g0SGNnT09malBiczlBUVpXYm1HYkpKRjRWRWZBaUI4ZUVLRi9WQllvWVhRREQzVHpLNUlEMkdzbXplMzhpNk56ek9ndHRMam9nPT0iLCJNSUlCNXpDQ0FZeWdBd0lCQWdJVUw2ZnJzdHdldjdZTWtPWVNuUHVlSlQyR3g1UXdDZ1lJS29aSXpqMEVBd0l3UmpFTE1Ba0dBMVVFQmhNQ1ZWTXhFekFSQmdOVkJBZ01DbE52YldVdFUzUmhkR1V4RGpBTUJnTlZCQW9NQlZaaGNHOXlNUkl3RUFZRFZRUUREQWx5YjI5MExXTmxjblF3SGhjTk1qTXhNREkwTVRNME1qTTFXaGNOTWpneE1ESXlNVE0wTWpNMVdqQk9NUXN3Q1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0F3S1UyOXRaUzFUZEdGMFpURU9NQXdHQTFVRUNnd0ZWbUZ3YjNJeEdqQVlCZ05WQkFNTUVXbHVkR1Z5YldWa2FXRjBaUzFqWlhKME1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRWt6WGFFQTlDSVpyUkVmQ0Mra05tM0pxZDdmR0ZFT05Ia2p5TFJ4NS83SUFYeHB4TGZ0WWNoOTU1K1VRNVhHOHdUZ2tNQ0NaNG9LRjhNMXg3Zkw3cXU2TlFNRTR3REFZRFZSMFRCQVV3QXdFQi96QWRCZ05WSFE0RUZnUVVyRU53VW02VDBSbmUxTW9MY3lWQ2NhVTVvTTB3SHdZRFZSMGpCQmd3Rm9BVVkxM3oxRVhHbjlVQmZwZ3BmVTl0UWJ2TVJRZ3dDZ1lJS29aSXpqMEVBd0lEU1FBd1JnSWhBSW04bStLb0RFbktBdUgrZUZROGJWSDJkc3p2NlcveCtwNE9zZERzd0VrNUFpRUF5bWd1SmdxQUpZU3NDdzdYM0pDVVBNY29LdGFRRzZNamhRdThrWlpCQUNJPSIsIk1JSUI0VENDQVllZ0F3SUJBZ0lVRG9PZWZlZkNOcS9UR1dyaUlzWUh2ejBMcE5Jd0NnWUlLb1pJemowRUF3SXdSakVMTUFrR0ExVUVCaE1DVlZNeEV6QVJCZ05WQkFnTUNsTnZiV1V0VTNSaGRHVXhEakFNQmdOVkJBb01CVlpoY0c5eU1SSXdFQVlEVlFRRERBbHliMjkwTFdObGNuUXdIaGNOTWpNeE1ESTBNVEl3T0RJM1doY05Nek14TURJeE1USXdPREkzV2pCR01Rc3dDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVDQXdLVTI5dFpTMVRkR0YwWlRFT01Bd0dBMVVFQ2d3RlZtRndiM0l4RWpBUUJnTlZCQU1NQ1hKdmIzUXRZMlZ5ZERCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQk5wditIRzUyak9UMVcrcjFrMTNiSm8yazlEeVJ5RmJ5Y0JwUHNXUUtmdDlueHdFSHZ6RGoxaXZvTWZhanhsTCtuL0ZMQm5Pblk2M21GV216YW9adkgralV6QlJNQjBHQTFVZERnUVdCQlJqWGZQVVJjYWYxUUYrbUNsOVQyMUJ1OHhGQ0RBZkJnTlZIU01FR0RBV2dCUmpYZlBVUmNhZjFRRittQ2w5VDIxQnU4eEZDREFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJR0lwWDlsbGlVMTM1VjgrTFk2L2NqQm1HcktLTmxZV0xMb1o2RGlhdXpkSkFpRUE5R1NBSUdoZk05a2JXbGtjak1zNmxBNHB3ZjRSZlVFRmVnaFlwWkticUZvPSJdfQ.eyJjb29sIjp0cnVlfQ.bqzLnIVtK4rU9eXhQnrWMpXPdWvxIcodDNI5BQsC-u_pAdaiO8ckbUs840c1WtWdGB7Zv7w7z7bwNWGAwM7WIQ
    """

let missingIntermediateToken = """
    eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlCanpDQ0FUVUNGSDhFWFBJbDBRbDQwYzdKOEhkK2R6QWgwY3dVTUFvR0NDcUdTTTQ5QkFNQ01FNHhDekFKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFJREFwVGIyMWxMVk4wWVhSbE1RNHdEQVlEVlFRS0RBVldZWEJ2Y2pFYU1CZ0dBMVVFQXd3UmFXNTBaWEp0WldScFlYUmxMV05sY25Rd0hoY05Nak14TURJME1UTTBNalU1V2hjTk1qUXhNREl6TVRNME1qVTVXakJHTVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNBd0tVMjl0WlMxVGRHRjBaVEVPTUF3R0ExVUVDZ3dGVm1Gd2IzSXhFakFRQmdOVkJBTU1DV3hsWVdZdFkyVnlkREJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCRU85VjZLQWhSR0l4QWx2Ukl6U3BtSVRmVVZiWHl5ZGMvZWdlbHpLLzZ3NDEySmc4RDJlSVRkOHVDRmxnVmh4WUlkR1pNN1hYUWhaNmhOZnE2S3JyUG93Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUxJaXhudE93V3o4NlFHa0g0SGNnT09malBiczlBUVpXYm1HYkpKRjRWRWZBaUI4ZUVLRi9WQllvWVhRREQzVHpLNUlEMkdzbXplMzhpNk56ek9ndHRMam9nPT0iLCJNSUlCNFRDQ0FZZWdBd0lCQWdJVURvT2VmZWZDTnEvVEdXcmlJc1lIdnowTHBOSXdDZ1lJS29aSXpqMEVBd0l3UmpFTE1Ba0dBMVVFQmhNQ1ZWTXhFekFSQmdOVkJBZ01DbE52YldVdFUzUmhkR1V4RGpBTUJnTlZCQW9NQlZaaGNHOXlNUkl3RUFZRFZRUUREQWx5YjI5MExXTmxjblF3SGhjTk1qTXhNREkwTVRJd09ESTNXaGNOTXpNeE1ESXhNVEl3T0RJM1dqQkdNUXN3Q1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0F3S1UyOXRaUzFUZEdGMFpURU9NQXdHQTFVRUNnd0ZWbUZ3YjNJeEVqQVFCZ05WQkFNTUNYSnZiM1F0WTJWeWREQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJOcHYrSEc1MmpPVDFXK3IxazEzYkpvMms5RHlSeUZieWNCcFBzV1FLZnQ5bnh3RUh2ekRqMWl2b01mYWp4bEwrbi9GTEJuT25ZNjNtRldtemFvWnZIK2pVekJSTUIwR0ExVWREZ1FXQkJSalhmUFVSY2FmMVFGK21DbDlUMjFCdTh4RkNEQWZCZ05WSFNNRUdEQVdnQlJqWGZQVVJjYWYxUUYrbUNsOVQyMUJ1OHhGQ0RBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSUdJcFg5bGxpVTEzNVY4K0xZNi9jakJtR3JLS05sWVdMTG9aNkRpYXV6ZEpBaUVBOUdTQUlHaGZNOWtiV2xrY2pNczZsQTRwd2Y0UmZVRUZlZ2hZcFpLYnFGbz0iXX0.eyJjb29sIjp0cnVlfQ.mqHyjgbPc0vtcOtflV8TUTEeG7X7Wrb_gfsYicn8zKP3xmcTFn96V1-QQgOeyLSGPR3iMz11CELXIUuPoRRfbw
    """

let missingRootToken = """
    eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlCanpDQ0FUVUNGSDhFWFBJbDBRbDQwYzdKOEhkK2R6QWgwY3dVTUFvR0NDcUdTTTQ5QkFNQ01FNHhDekFKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFJREFwVGIyMWxMVk4wWVhSbE1RNHdEQVlEVlFRS0RBVldZWEJ2Y2pFYU1CZ0dBMVVFQXd3UmFXNTBaWEp0WldScFlYUmxMV05sY25Rd0hoY05Nak14TURJME1UTTBNalU1V2hjTk1qUXhNREl6TVRNME1qVTVXakJHTVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNBd0tVMjl0WlMxVGRHRjBaVEVPTUF3R0ExVUVDZ3dGVm1Gd2IzSXhFakFRQmdOVkJBTU1DV3hsWVdZdFkyVnlkREJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCRU85VjZLQWhSR0l4QWx2Ukl6U3BtSVRmVVZiWHl5ZGMvZWdlbHpLLzZ3NDEySmc4RDJlSVRkOHVDRmxnVmh4WUlkR1pNN1hYUWhaNmhOZnE2S3JyUG93Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUxJaXhudE93V3o4NlFHa0g0SGNnT09malBiczlBUVpXYm1HYkpKRjRWRWZBaUI4ZUVLRi9WQllvWVhRREQzVHpLNUlEMkdzbXplMzhpNk56ek9ndHRMam9nPT0iLCJNSUlCNXpDQ0FZeWdBd0lCQWdJVUw2ZnJzdHdldjdZTWtPWVNuUHVlSlQyR3g1UXdDZ1lJS29aSXpqMEVBd0l3UmpFTE1Ba0dBMVVFQmhNQ1ZWTXhFekFSQmdOVkJBZ01DbE52YldVdFUzUmhkR1V4RGpBTUJnTlZCQW9NQlZaaGNHOXlNUkl3RUFZRFZRUUREQWx5YjI5MExXTmxjblF3SGhjTk1qTXhNREkwTVRNME1qTTFXaGNOTWpneE1ESXlNVE0wTWpNMVdqQk9NUXN3Q1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0F3S1UyOXRaUzFUZEdGMFpURU9NQXdHQTFVRUNnd0ZWbUZ3YjNJeEdqQVlCZ05WQkFNTUVXbHVkR1Z5YldWa2FXRjBaUzFqWlhKME1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRWt6WGFFQTlDSVpyUkVmQ0Mra05tM0pxZDdmR0ZFT05Ia2p5TFJ4NS83SUFYeHB4TGZ0WWNoOTU1K1VRNVhHOHdUZ2tNQ0NaNG9LRjhNMXg3Zkw3cXU2TlFNRTR3REFZRFZSMFRCQVV3QXdFQi96QWRCZ05WSFE0RUZnUVVyRU53VW02VDBSbmUxTW9MY3lWQ2NhVTVvTTB3SHdZRFZSMGpCQmd3Rm9BVVkxM3oxRVhHbjlVQmZwZ3BmVTl0UWJ2TVJRZ3dDZ1lJS29aSXpqMEVBd0lEU1FBd1JnSWhBSW04bStLb0RFbktBdUgrZUZROGJWSDJkc3p2NlcveCtwNE9zZERzd0VrNUFpRUF5bWd1SmdxQUpZU3NDdzdYM0pDVVBNY29LdGFRRzZNamhRdThrWlpCQUNJPSJdfQ.eyJjb29sIjp0cnVlfQ.d7AmnXaDUu1eU5ufBQ5ruailzBbJVud3RtqAcDYApvP6fPC1SttYmDKbsjUHx4q-NEt14n6xZ0Np_zy-OtM6lw
    """

let missingLeafToken = """
    eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlCNXpDQ0FZeWdBd0lCQWdJVUw2ZnJzdHdldjdZTWtPWVNuUHVlSlQyR3g1UXdDZ1lJS29aSXpqMEVBd0l3UmpFTE1Ba0dBMVVFQmhNQ1ZWTXhFekFSQmdOVkJBZ01DbE52YldVdFUzUmhkR1V4RGpBTUJnTlZCQW9NQlZaaGNHOXlNUkl3RUFZRFZRUUREQWx5YjI5MExXTmxjblF3SGhjTk1qTXhNREkwTVRNME1qTTFXaGNOTWpneE1ESXlNVE0wTWpNMVdqQk9NUXN3Q1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0F3S1UyOXRaUzFUZEdGMFpURU9NQXdHQTFVRUNnd0ZWbUZ3YjNJeEdqQVlCZ05WQkFNTUVXbHVkR1Z5YldWa2FXRjBaUzFqWlhKME1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRWt6WGFFQTlDSVpyUkVmQ0Mra05tM0pxZDdmR0ZFT05Ia2p5TFJ4NS83SUFYeHB4TGZ0WWNoOTU1K1VRNVhHOHdUZ2tNQ0NaNG9LRjhNMXg3Zkw3cXU2TlFNRTR3REFZRFZSMFRCQVV3QXdFQi96QWRCZ05WSFE0RUZnUVVyRU53VW02VDBSbmUxTW9MY3lWQ2NhVTVvTTB3SHdZRFZSMGpCQmd3Rm9BVVkxM3oxRVhHbjlVQmZwZ3BmVTl0UWJ2TVJRZ3dDZ1lJS29aSXpqMEVBd0lEU1FBd1JnSWhBSW04bStLb0RFbktBdUgrZUZROGJWSDJkc3p2NlcveCtwNE9zZERzd0VrNUFpRUF5bWd1SmdxQUpZU3NDdzdYM0pDVVBNY29LdGFRRzZNamhRdThrWlpCQUNJPSIsIk1JSUI0VENDQVllZ0F3SUJBZ0lVRG9PZWZlZkNOcS9UR1dyaUlzWUh2ejBMcE5Jd0NnWUlLb1pJemowRUF3SXdSakVMTUFrR0ExVUVCaE1DVlZNeEV6QVJCZ05WQkFnTUNsTnZiV1V0VTNSaGRHVXhEakFNQmdOVkJBb01CVlpoY0c5eU1SSXdFQVlEVlFRRERBbHliMjkwTFdObGNuUXdIaGNOTWpNeE1ESTBNVEl3T0RJM1doY05Nek14TURJeE1USXdPREkzV2pCR01Rc3dDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVDQXdLVTI5dFpTMVRkR0YwWlRFT01Bd0dBMVVFQ2d3RlZtRndiM0l4RWpBUUJnTlZCQU1NQ1hKdmIzUXRZMlZ5ZERCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQk5wditIRzUyak9UMVcrcjFrMTNiSm8yazlEeVJ5RmJ5Y0JwUHNXUUtmdDlueHdFSHZ6RGoxaXZvTWZhanhsTCtuL0ZMQm5Pblk2M21GV216YW9adkgralV6QlJNQjBHQTFVZERnUVdCQlJqWGZQVVJjYWYxUUYrbUNsOVQyMUJ1OHhGQ0RBZkJnTlZIU01FR0RBV2dCUmpYZlBVUmNhZjFRRittQ2w5VDIxQnU4eEZDREFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJR0lwWDlsbGlVMTM1VjgrTFk2L2NqQm1HcktLTmxZV0xMb1o2RGlhdXpkSkFpRUE5R1NBSUdoZk05a2JXbGtjak1zNmxBNHB3ZjRSZlVFRmVnaFlwWkticUZvPSJdfQ.eyJjb29sIjp0cnVlfQ.nky-7PNeo6TX1Vtr3ci5pAERNo20Dzcd41LBry3XzSDyFrz1I14836c8skKGT4M7GWn5rB_w0GAA3inZPusiAA
    """

let missingLeafAndIntermediateToken = """
    eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlCNFRDQ0FZZWdBd0lCQWdJVURvT2VmZWZDTnEvVEdXcmlJc1lIdnowTHBOSXdDZ1lJS29aSXpqMEVBd0l3UmpFTE1Ba0dBMVVFQmhNQ1ZWTXhFekFSQmdOVkJBZ01DbE52YldVdFUzUmhkR1V4RGpBTUJnTlZCQW9NQlZaaGNHOXlNUkl3RUFZRFZRUUREQWx5YjI5MExXTmxjblF3SGhjTk1qTXhNREkwTVRJd09ESTNXaGNOTXpNeE1ESXhNVEl3T0RJM1dqQkdNUXN3Q1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0F3S1UyOXRaUzFUZEdGMFpURU9NQXdHQTFVRUNnd0ZWbUZ3YjNJeEVqQVFCZ05WQkFNTUNYSnZiM1F0WTJWeWREQlpNQk1HQnlxR1NNNDlBZ0VHQ0NxR1NNNDlBd0VIQTBJQUJOcHYrSEc1MmpPVDFXK3IxazEzYkpvMms5RHlSeUZieWNCcFBzV1FLZnQ5bnh3RUh2ekRqMWl2b01mYWp4bEwrbi9GTEJuT25ZNjNtRldtemFvWnZIK2pVekJSTUIwR0ExVWREZ1FXQkJSalhmUFVSY2FmMVFGK21DbDlUMjFCdTh4RkNEQWZCZ05WSFNNRUdEQVdnQlJqWGZQVVJjYWYxUUYrbUNsOVQyMUJ1OHhGQ0RBUEJnTlZIUk1CQWY4RUJUQURBUUgvTUFvR0NDcUdTTTQ5QkFNQ0EwZ0FNRVVDSUdJcFg5bGxpVTEzNVY4K0xZNi9jakJtR3JLS05sWVdMTG9aNkRpYXV6ZEpBaUVBOUdTQUlHaGZNOWtiV2xrY2pNczZsQTRwd2Y0UmZVRUZlZ2hZcFpLYnFGbz0iXX0.eyJjb29sIjp0cnVlfQ.9Dy7P8zp3GSXxw7QQgvhS0lLaLl0yIt1Mmo2-Nt7EJIr7lvVMSvlDHzDk7PmAnocm7MBWGKdfwo7b0GIdblgLA
    """

let missingIntermediateAndRootToken = """
    eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlCanpDQ0FUVUNGSDhFWFBJbDBRbDQwYzdKOEhkK2R6QWgwY3dVTUFvR0NDcUdTTTQ5QkFNQ01FNHhDekFKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFJREFwVGIyMWxMVk4wWVhSbE1RNHdEQVlEVlFRS0RBVldZWEJ2Y2pFYU1CZ0dBMVVFQXd3UmFXNTBaWEp0WldScFlYUmxMV05sY25Rd0hoY05Nak14TURJME1UTTBNalU1V2hjTk1qUXhNREl6TVRNME1qVTVXakJHTVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNBd0tVMjl0WlMxVGRHRjBaVEVPTUF3R0ExVUVDZ3dGVm1Gd2IzSXhFakFRQmdOVkJBTU1DV3hsWVdZdFkyVnlkREJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCRU85VjZLQWhSR0l4QWx2Ukl6U3BtSVRmVVZiWHl5ZGMvZWdlbHpLLzZ3NDEySmc4RDJlSVRkOHVDRmxnVmh4WUlkR1pNN1hYUWhaNmhOZnE2S3JyUG93Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUxJaXhudE93V3o4NlFHa0g0SGNnT09malBiczlBUVpXYm1HYkpKRjRWRWZBaUI4ZUVLRi9WQllvWVhRREQzVHpLNUlEMkdzbXplMzhpNk56ek9ndHRMam9nPT0iXX0.eyJjb29sIjp0cnVlfQ.kYaJBFl8CVD-wZwaPd_G3oIjCyawHW-8nAQcpP3gzM1AMMm0V7w83cKczNXCWvqnGd-jE8xLAcBpOJ6ZINqH2Q
    """

let expiredLeafToken = """
    eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlCbHpDQ0FUMENGQmdtUFlSaE1nY0VQbnhkOE8xSjlyU09ML2psTUFvR0NDcUdTTTQ5QkFNQ01FNHhDekFKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFJREFwVGIyMWxMVk4wWVhSbE1RNHdEQVlEVlFRS0RBVldZWEJ2Y2pFYU1CZ0dBMVVFQXd3UmFXNTBaWEp0WldScFlYUmxMV05sY25Rd0hoY05Nak14TURJME1UTTFOVE0zV2hjTk1qTXhNREl6TVRNMU5UTTNXakJPTVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNBd0tVMjl0WlMxVGRHRjBaVEVPTUF3R0ExVUVDZ3dGVm1Gd2IzSXhHakFZQmdOVkJBTU1FV1Y0Y0dseVpXUXRiR1ZoWmkxalpYSjBNRmt3RXdZSEtvWkl6ajBDQVFZSUtvWkl6ajBEQVFjRFFnQUV5V1o0b3J1VEpjTzIzakJoMlZDZys0KzI2d1QrYXNwaDhxbUVYakpuZVlwMW9LQlFmYjc2RENqN1lUWlgzeEk1Q2JDVUhzbndOT1B3ZllkOUZqRjdZVEFLQmdncWhrak9QUVFEQWdOSUFEQkZBaUVBdjUzV2V5RHFUSnczTFRGdGFiS05qanFaOEZOY1YvRUNoeGU3cHdaenlmOENJRUlsN20xRnZmQ3FFR1lMcDdsZ0RnckRXY1pMKy9XZ1BVdjhpck5hSVpCUiIsIk1JSUI1ekNDQVl5Z0F3SUJBZ0lVTDZmcnN0d2V2N1lNa09ZU25QdWVKVDJHeDVRd0NnWUlLb1pJemowRUF3SXdSakVMTUFrR0ExVUVCaE1DVlZNeEV6QVJCZ05WQkFnTUNsTnZiV1V0VTNSaGRHVXhEakFNQmdOVkJBb01CVlpoY0c5eU1SSXdFQVlEVlFRRERBbHliMjkwTFdObGNuUXdIaGNOTWpNeE1ESTBNVE0wTWpNMVdoY05Namd4TURJeU1UTTBNak0xV2pCT01Rc3dDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVDQXdLVTI5dFpTMVRkR0YwWlRFT01Bd0dBMVVFQ2d3RlZtRndiM0l4R2pBWUJnTlZCQU1NRVdsdWRHVnliV1ZrYVdGMFpTMWpaWEowTUZrd0V3WUhLb1pJemowQ0FRWUlLb1pJemowREFRY0RRZ0FFa3pYYUVBOUNJWnJSRWZDQytrTm0zSnFkN2ZHRkVPTkhranlMUng1LzdJQVh4cHhMZnRZY2g5NTUrVVE1WEc4d1Rna01DQ1o0b0tGOE0xeDdmTDdxdTZOUU1FNHdEQVlEVlIwVEJBVXdBd0VCL3pBZEJnTlZIUTRFRmdRVXJFTndVbTZUMFJuZTFNb0xjeVZDY2FVNW9NMHdId1lEVlIwakJCZ3dGb0FVWTEzejFFWEduOVVCZnBncGZVOXRRYnZNUlFnd0NnWUlLb1pJemowRUF3SURTUUF3UmdJaEFJbThtK0tvREVuS0F1SCtlRlE4YlZIMmRzenY2Vy94K3A0T3NkRHN3RWs1QWlFQXltZ3VKZ3FBSllTc0N3N1gzSkNVUE1jb0t0YVFHNk1qaFF1OGtaWkJBQ0k9IiwiTUlJQjRUQ0NBWWVnQXdJQkFnSVVEb09lZmVmQ05xL1RHV3JpSXNZSHZ6MExwTkl3Q2dZSUtvWkl6ajBFQXdJd1JqRUxNQWtHQTFVRUJoTUNWVk14RXpBUkJnTlZCQWdNQ2xOdmJXVXRVM1JoZEdVeERqQU1CZ05WQkFvTUJWWmhjRzl5TVJJd0VBWURWUVFEREFseWIyOTBMV05sY25Rd0hoY05Nak14TURJME1USXdPREkzV2hjTk16TXhNREl4TVRJd09ESTNXakJHTVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNBd0tVMjl0WlMxVGRHRjBaVEVPTUF3R0ExVUVDZ3dGVm1Gd2IzSXhFakFRQmdOVkJBTU1DWEp2YjNRdFkyVnlkREJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCTnB2K0hHNTJqT1QxVytyMWsxM2JKbzJrOUR5UnlGYnljQnBQc1dRS2Z0OW54d0VIdnpEajFpdm9NZmFqeGxMK24vRkxCbk9uWTYzbUZXbXphb1p2SCtqVXpCUk1CMEdBMVVkRGdRV0JCUmpYZlBVUmNhZjFRRittQ2w5VDIxQnU4eEZDREFmQmdOVkhTTUVHREFXZ0JSalhmUFVSY2FmMVFGK21DbDlUMjFCdTh4RkNEQVBCZ05WSFJNQkFmOEVCVEFEQVFIL01Bb0dDQ3FHU000OUJBTUNBMGdBTUVVQ0lHSXBYOWxsaVUxMzVWOCtMWTYvY2pCbUdyS0tObFlXTExvWjZEaWF1emRKQWlFQTlHU0FJR2hmTTlrYldsa2NqTXM2bEE0cHdmNFJmVUVGZWdoWXBaS2JxRm89Il19.eyJjb29sIjpmYWxzZX0.0J41d6x1AsJz7kVrBtJKqeQV8mSdb7tYDQXQjPCuHLktAz2b3m1WfrScQ3Vz4lz2Yzb_dKBrX9M9kQP16Nx1Bw
    """

let validButNotCoolToken = """
    eyJhbGciOiJFUzI1NiIsInR5cCI6IkpXVCIsIng1YyI6WyJNSUlCanpDQ0FUVUNGSDhFWFBJbDBRbDQwYzdKOEhkK2R6QWgwY3dVTUFvR0NDcUdTTTQ5QkFNQ01FNHhDekFKQmdOVkJBWVRBbFZUTVJNd0VRWURWUVFJREFwVGIyMWxMVk4wWVhSbE1RNHdEQVlEVlFRS0RBVldZWEJ2Y2pFYU1CZ0dBMVVFQXd3UmFXNTBaWEp0WldScFlYUmxMV05sY25Rd0hoY05Nak14TURJME1UTTBNalU1V2hjTk1qUXhNREl6TVRNME1qVTVXakJHTVFzd0NRWURWUVFHRXdKVlV6RVRNQkVHQTFVRUNBd0tVMjl0WlMxVGRHRjBaVEVPTUF3R0ExVUVDZ3dGVm1Gd2IzSXhFakFRQmdOVkJBTU1DV3hsWVdZdFkyVnlkREJaTUJNR0J5cUdTTTQ5QWdFR0NDcUdTTTQ5QXdFSEEwSUFCRU85VjZLQWhSR0l4QWx2Ukl6U3BtSVRmVVZiWHl5ZGMvZWdlbHpLLzZ3NDEySmc4RDJlSVRkOHVDRmxnVmh4WUlkR1pNN1hYUWhaNmhOZnE2S3JyUG93Q2dZSUtvWkl6ajBFQXdJRFNBQXdSUUloQUxJaXhudE93V3o4NlFHa0g0SGNnT09malBiczlBUVpXYm1HYkpKRjRWRWZBaUI4ZUVLRi9WQllvWVhRREQzVHpLNUlEMkdzbXplMzhpNk56ek9ndHRMam9nPT0iLCJNSUlCNXpDQ0FZeWdBd0lCQWdJVUw2ZnJzdHdldjdZTWtPWVNuUHVlSlQyR3g1UXdDZ1lJS29aSXpqMEVBd0l3UmpFTE1Ba0dBMVVFQmhNQ1ZWTXhFekFSQmdOVkJBZ01DbE52YldVdFUzUmhkR1V4RGpBTUJnTlZCQW9NQlZaaGNHOXlNUkl3RUFZRFZRUUREQWx5YjI5MExXTmxjblF3SGhjTk1qTXhNREkwTVRNME1qTTFXaGNOTWpneE1ESXlNVE0wTWpNMVdqQk9NUXN3Q1FZRFZRUUdFd0pWVXpFVE1CRUdBMVVFQ0F3S1UyOXRaUzFUZEdGMFpURU9NQXdHQTFVRUNnd0ZWbUZ3YjNJeEdqQVlCZ05WQkFNTUVXbHVkR1Z5YldWa2FXRjBaUzFqWlhKME1Ga3dFd1lIS29aSXpqMENBUVlJS29aSXpqMERBUWNEUWdBRWt6WGFFQTlDSVpyUkVmQ0Mra05tM0pxZDdmR0ZFT05Ia2p5TFJ4NS83SUFYeHB4TGZ0WWNoOTU1K1VRNVhHOHdUZ2tNQ0NaNG9LRjhNMXg3Zkw3cXU2TlFNRTR3REFZRFZSMFRCQVV3QXdFQi96QWRCZ05WSFE0RUZnUVVyRU53VW02VDBSbmUxTW9MY3lWQ2NhVTVvTTB3SHdZRFZSMGpCQmd3Rm9BVVkxM3oxRVhHbjlVQmZwZ3BmVTl0UWJ2TVJRZ3dDZ1lJS29aSXpqMEVBd0lEU1FBd1JnSWhBSW04bStLb0RFbktBdUgrZUZROGJWSDJkc3p2NlcveCtwNE9zZERzd0VrNUFpRUF5bWd1SmdxQUpZU3NDdzdYM0pDVVBNY29LdGFRRzZNamhRdThrWlpCQUNJPSIsIk1JSUI0VENDQVllZ0F3SUJBZ0lVRG9PZWZlZkNOcS9UR1dyaUlzWUh2ejBMcE5Jd0NnWUlLb1pJemowRUF3SXdSakVMTUFrR0ExVUVCaE1DVlZNeEV6QVJCZ05WQkFnTUNsTnZiV1V0VTNSaGRHVXhEakFNQmdOVkJBb01CVlpoY0c5eU1SSXdFQVlEVlFRRERBbHliMjkwTFdObGNuUXdIaGNOTWpNeE1ESTBNVEl3T0RJM1doY05Nek14TURJeE1USXdPREkzV2pCR01Rc3dDUVlEVlFRR0V3SlZVekVUTUJFR0ExVUVDQXdLVTI5dFpTMVRkR0YwWlRFT01Bd0dBMVVFQ2d3RlZtRndiM0l4RWpBUUJnTlZCQU1NQ1hKdmIzUXRZMlZ5ZERCWk1CTUdCeXFHU000OUFnRUdDQ3FHU000OUF3RUhBMElBQk5wditIRzUyak9UMVcrcjFrMTNiSm8yazlEeVJ5RmJ5Y0JwUHNXUUtmdDlueHdFSHZ6RGoxaXZvTWZhanhsTCtuL0ZMQm5Pblk2M21GV216YW9adkgralV6QlJNQjBHQTFVZERnUVdCQlJqWGZQVVJjYWYxUUYrbUNsOVQyMUJ1OHhGQ0RBZkJnTlZIU01FR0RBV2dCUmpYZlBVUmNhZjFRRittQ2w5VDIxQnU4eEZDREFQQmdOVkhSTUJBZjhFQlRBREFRSC9NQW9HQ0NxR1NNNDlCQU1DQTBnQU1FVUNJR0lwWDlsbGlVMTM1VjgrTFk2L2NqQm1HcktLTmxZV0xMb1o2RGlhdXpkSkFpRUE5R1NBSUdoZk05a2JXbGtjak1zNmxBNHB3ZjRSZlVFRmVnaFlwWkticUZvPSJdfQ.eyJjb29sIjpmYWxzZX0.JtNl3uCSJ7rycwW__0o1xARr0y5XYsXUc2Ltx1W2IKmBmn66vAOEY2Eur9Xy40eX8qMr8GrxsGmzia5YEN3ugQ
    """

let x5cCerts = [
    """
    -----BEGIN CERTIFICATE-----
    MIIBpDCCAUkCFHVcsASQJGJi6BI+7apcSVrcWaAAMAoGCCqGSM49BAMCMFMxCzAJ
    BgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0YXRlMSEwHwYDVQQKDBhJbnRlcm5l
    dCBXaWRnaXRzIFB0eSBMdGQxDDAKBgNVBAMMA1llczAeFw0yMzExMjMyMTQwNDha
    Fw0yNDExMjIyMTQwNDhaMFUxCzAJBgNVBAYTAkFVMRMwEQYDVQQIDApTb21lLVN0
    YXRlMSEwHwYDVQQKDBhJbnRlcm5ldCBXaWRnaXRzIFB0eSBMdGQxDjAMBgNVBAMM
    BU1heWJlMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEORJB5yvqxuG7+EgBDUK/
    BjjE1SFU2w+EZkhhLDUmnXdujwuVvNuoEAhXXpKXJA0lMXUL3VpYkjfPokElxKow
    yjAKBggqhkjOPQQDAgNJADBGAiEAs11xN77nyLwfnLupy957CdUQZwEj5kfGD/UA
    deOvPx8CIQDD0BAEP10e3SdkQYBLtvmIfR8LEtf1FN9LpeRFjMsd0Q==
    -----END CERTIFICATE-----
    """,
    """
    -----BEGIN CERTIFICATE-----
    MIIB9zCCAZ2gAwIBAgIURyU7Zx4xpWe/qgQ/o5WWDKO1QAkwCgYIKoZIzj0EAwIw
    UjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
    dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDELMAkGA1UEAwwCTm8wHhcNMjMxMTIzMjE0
    MDM4WhcNMjgxMTIxMjE0MDM4WjBTMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29t
    ZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQwwCgYD
    VQQDDANZZXMwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQtXAr2JmHbVbVcCOsE
    C2HVYbZjj9jNJHSDRRJPo/pRjx6INrcO6ff2SLh+Y0pTy9ztSP0JkK8sOmx1MGDU
    VS8uo1AwTjAMBgNVHRMEBTADAQH/MB0GA1UdDgQWBBR91V3hyIdfdXR/k49UAauW
    M7MsuzAfBgNVHSMEGDAWgBQKOxtgWctssvjCMrI3s5ifF6rpojAKBggqhkjOPQQD
    AgNIADBFAiEAphZb4dN19p+UBVMe1UgMVORQ6I14Z96/F+17umwDgfACIF9lGumM
    Fr8KVqiSUvfHyaaqXGrrP9dExVLSqcAaPyPr
    -----END CERTIFICATE-----
    """,
    """
    -----BEGIN CERTIFICATE-----
    MIIB+jCCAZ+gAwIBAgIUDSttzLVHb8h1sQTQTSN6hrR2oSUwCgYIKoZIzj0EAwIw
    UjELMAkGA1UEBhMCQVUxEzARBgNVBAgMClNvbWUtU3RhdGUxITAfBgNVBAoMGElu
    dGVybmV0IFdpZGdpdHMgUHR5IEx0ZDELMAkGA1UEAwwCTm8wHhcNMjMxMTIzMjE0
    MDM0WhcNMzMxMTIwMjE0MDM0WjBSMQswCQYDVQQGEwJBVTETMBEGA1UECAwKU29t
    ZS1TdGF0ZTEhMB8GA1UECgwYSW50ZXJuZXQgV2lkZ2l0cyBQdHkgTHRkMQswCQYD
    VQQDDAJObzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBdNKGGwi8EOZL+yEuBM
    n0+L0cHiUxBvUW6BkXkLwP0YgkSQ5S3rPplsGp+U7SotTHl9pqsPW2ErnA7V12zU
    E1WjUzBRMB0GA1UdDgQWBBQKOxtgWctssvjCMrI3s5ifF6rpojAfBgNVHSMEGDAW
    gBQKOxtgWctssvjCMrI3s5ifF6rpojAPBgNVHRMBAf8EBTADAQH/MAoGCCqGSM49
    BAMCA0kAMEYCIQCf4tM5SmcWmN6/7zNfjfLV1N3IBTO68cub3PpYurQUKAIhALwO
    oqoVTtJyc2qmFL/EYTcXZU8VwpBJOtQVxjxPI+8s
    -----END CERTIFICATE-----
    """,
]

let x5cLeafCertKey = """
    -----BEGIN EC PRIVATE KEY-----
    MHcCAQEEICqzgINLJICNbFxXI9rYvKGL3g1bCJTjQGIIz9AvfRjBoAoGCCqGSM49
    AwEHoUQDQgAEORJB5yvqxuG7+EgBDUK/BjjE1SFU2w+EZkhhLDUmnXdujwuVvNuo
    EAhXXpKXJA0lMXUL3VpYkjfPokElxKowyg==
    -----END EC PRIVATE KEY-----
    """

let rootCA = try! Certificate(
    derEncoded: Array(
        Data(
            base64Encoded:
                "MIIBgjCCASmgAwIBAgIJALUc5ALiH5pbMAoGCCqGSM49BAMDMDYxCzAJBgNVBAYTAlVTMRMwEQYDVQQIDApDYWxpZm9ybmlhMRIwEAYDVQQHDAlDdXBlcnRpbm8wHhcNMjMwMTA1MjEzMDIyWhcNMzMwMTAyMjEzMDIyWjA2MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJQ3VwZXJ0aW5vMFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAEc+/Bl+gospo6tf9Z7io5tdKdrlN1YdVnqEhEDXDShzdAJPQijamXIMHf8xWWTa1zgoYTxOKpbuJtDplz1XriTaMgMB4wDAYDVR0TBAUwAwEB/zAOBgNVHQ8BAf8EBAMCAQYwCgYIKoZIzj0EAwMDRwAwRAIgemWQXnMAdTad2JDJWng9U4uBBL5mA7WI05H7oH7c6iQCIHiRqMjNfzUAyiu9h6rOU/K+iTR0I/3Y/NSWsXHX+acc"
        )!))
let leaf = try! Certificate(
    derEncoded: Array(
        Data(
            base64Encoded:
                "MIIBoDCCAUagAwIBAgIBDDAKBggqhkjOPQQDAzBFMQswCQYDVQQGEwJVUzELMAkGA1UECAwCQ0ExEjAQBgNVBAcMCUN1cGVydGlubzEVMBMGA1UECgwMSW50ZXJtZWRpYXRlMB4XDTIzMDEwNTIxMzEzNFoXDTMzMDEwMTIxMzEzNFowPTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYDVQQHDAlDdXBlcnRpbm8xDTALBgNVBAoMBExlYWYwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAATitYHEaYVuc8g9AjTOwErMvGyPykPa+puvTI8hJTHZZDLGas2qX1+ErxgQTJgVXv76nmLhhRJH+j25AiAI8iGsoy8wLTAJBgNVHRMEAjAAMA4GA1UdDwEB/wQEAwIHgDAQBgoqhkiG92NkBgsBBAIFADAKBggqhkjOPQQDAwNIADBFAiBX4c+T0Fp5nJ5QRClRfu5PSByRvNPtuaTsk0vPB3WAIAIhANgaauAj/YP9s0AkEhyJhxQO/6Q2zouZ+H1CIOehnMzQ"
        )!))
let intermediate = try! Certificate(
    derEncoded: Array(
        Data(
            base64Encoded:
                "MIIBnzCCAUWgAwIBAgIBCzAKBggqhkjOPQQDAzA2MQswCQYDVQQGEwJVUzETMBEGA1UECAwKQ2FsaWZvcm5pYTESMBAGA1UEBwwJQ3VwZXJ0aW5vMB4XDTIzMDEwNTIxMzEwNVoXDTMzMDEwMTIxMzEwNVowRTELMAkGA1UEBhMCVVMxCzAJBgNVBAgMAkNBMRIwEAYDVQQHDAlDdXBlcnRpbm8xFTATBgNVBAoMDEludGVybWVkaWF0ZTBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABBUN5V9rKjfRiMAIojEA0Av5Mp0oF+O0cL4gzrTF178inUHugj7Et46NrkQ7hKgMVnjogq45Q1rMs+cMHVNILWqjNTAzMA8GA1UdEwQIMAYBAf8CAQAwDgYDVR0PAQH/BAQDAgEGMBAGCiqGSIb3Y2QGAgEEAgUAMAoGCCqGSM49BAMDA0gAMEUCIQCmsIKYs41ullssHX4rVveUT0Z7Is5/hLK1lFPTtun3hAIgc2+2RG5+gNcFVcs+XJeEl4GZ+ojl3ROOmll+ye7dynQ="
        )!))

/// Each token has the following payload:
///
///     {
///        "cool" : true
///     }
private struct TokenPayload: JWTPayload {
    var cool: BoolClaim

    func verify(using _: some JWTAlgorithm) throws {
        if !cool.value {
            throw JWTError.claimVerificationFailure(failedClaim: cool, reason: "not cool")
        }
    }
}
