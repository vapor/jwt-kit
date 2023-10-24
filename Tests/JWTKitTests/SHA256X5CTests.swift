import Foundation
import XCTest
#if os(Linux)
    import FoundationNetworking
#endif
@testable import JWTKit

/// This test suite is basically the same as the `X5CTests` suite,
/// but it uses the certificates hashed with SHA256 instead of the SHA1.
final class SHA256X5CTests: XCTestCase {
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
        """,
    ])

    func check(
        token: String
    ) throws {
        _ = try verifier.verifyJWS(
            token,
            as: TokenPayload.self
        )
    }

    /// x5c: [leaf, intermediate, root]
    ///
    /// Should pass validation.
    func testValidChain() throws {
        XCTAssertNoThrow(try check(token: validToken))
    }

    /// x5c: [leaf, root]
    ///
    /// Should fail validation.
    func testMissingIntermediate() throws {
        XCTAssertThrowsError(try check(token: missingIntermediateToken), "Missing intermediate cert should throw an error.")
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
    func testMissingRoot() throws {
        XCTAssertNoThrow(try check(token: validToken), "Missing root cert is fine, since we know what root we expect.")
    }

    /// x5c: [intermediate, root]
    ///
    /// Should fail validation.
    func testMissingLeaf() throws {
        XCTAssertThrowsError(try check(token: missingLeafToken), "Missing leaf cert should throw an error.")
    }

    /// x5c: [root]
    ///
    /// Should fail validation.
    func testMissingLeafAndIntermediate() throws {
        XCTAssertThrowsError(try check(token: missingLeafAndIntermediateToken), "Missing leaf/intermediate cert should throw an error.")
    }

    /// x5c: [expired_leaf, intermediate, root]
    ///
    /// Should fail validation because leaf is epxired.
    func testExpiredLeaf() throws {
        XCTAssertThrowsError(try check(token: expiredLeafToken), "Expired leaf token is invalid.")
    }

    /// x5c: [leaf]
    ///
    /// Should fail validation.
    func testMissingIntermediateAndRoot() throws {
        XCTAssertThrowsError(try check(token: missingIntermediateAndRootToken), "Missing intermediate/root cert should throw an error.")
    }

    /// x5c: [leaf, intermediate, root]
    ///
    /// Should fail validation because it's not cool!
    ///
    /// This is a test to make sure that the claims actually
    /// get verified.
    func testValidButNotCool() throws {
        XCTAssertThrowsError(try check(token: validButNotCoolToken), "Token isn't cool. Claims weren't verified.")
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

private struct TokenPayload: JWTPayload {
    var cool: Bool

    func verify(using _: JWTSigner) throws {
        if !cool {
            throw JWTError.claimVerificationFailure(name: "cool", reason: "not cool")
        }
    }
}
