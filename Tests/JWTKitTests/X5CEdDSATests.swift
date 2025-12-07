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
struct X5CEdDSATests {

    @Test("Test signing with x5c chain")
    func signWithX5CChain() async throws {
        let key = try EdDSA.PrivateKey()
        let privateKey = try Certificate.PrivateKey(pemEncoded: key.pemRepresentation)
        let subjectName = try DistinguishedName {
            CommonName("Nuw")
        }
        let cert = try Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: privateKey.publicKey,
            notValidBefore: Date(),
            notValidAfter: Date().addingTimeInterval(3600),
            issuer: subjectName,
            subject: subjectName,
            extensions: try Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                Critical(
                    KeyUsage(digitalSignature: true, keyCertSign: true)
                )
                //SubjectAlternativeNames([.dnsName("localhost")])
            },
            issuerPrivateKey: privateKey
        )
        let keyCollection = await JWTKeyCollection()
            .add(eddsa: key)
            /*.add(
                ecdsa: ES256PrivateKey(pem: x5cLeafCertKey)
            )*/

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let certs = [try cert.serializeAsPEM().pemString]
        let header: JWTHeader = ["x5c": .array(certs.map(JWTHeaderField.string))]
        let token = try await keyCollection.sign(payload, header: header)
        print("\n **** token=\(token)")
        let parsed = try DefaultJWTParser().parse(token.bytes, as: TestPayload.self)

        let x5c = try #require(parsed.header.x5c)
        //let pemCerts = try x5c.map(getPEMString)
        //#expect(pemCerts == x5cCerts)
        let verifier = try X5CVerifier(rootCertificates: certs)
        await #expect(throws: Never.self) {
            try await verifier.verifyJWS(token, as: TestPayload.self)
        }
    }
}


#endif  // canImport(Testing)
