@testable import JWTKit
import XCTest

final class InternalTests: XCTestCase {
    // MARK: ECDSA

    func testGetECParametersES256() async throws {
        let message = "test".bytes

        let ec = ES256PrivateKey()
        let keys = await JWTKeyCollection().addES256(key: ec, kid: "initial")

        let signature = try await keys.getKey(for: "initial").sign(message)

        let params = ec.parameters!
        try await keys.addES256(key: ES256PublicKey(parameters: params), kid: "params")
        try await XCTAssertTrueAsync(try await keys.getKey(for: "params").verify(signature, signs: message))
        XCTAssertEqual(ec.curve, .p256)
    }

    func testGetECParametersES384() async throws {
        let message = "test".bytes

        let ec = ES384PrivateKey()
        let keys = await JWTKeyCollection().addES384(key: ec, kid: "initial")

        let signature = try await keys.getKey(for: "initial").sign(message)

        let params = ec.parameters!
        try await keys.addES384(key: ES384PublicKey(parameters: params), kid: "params")
        try await XCTAssertTrueAsync(try await keys.getKey(for: "params").verify(signature, signs: message))
        XCTAssertEqual(ec.curve, .p384)
    }

    func testGetECParametersES512() async throws {
        let message = "test".bytes

        let ec = ES512PrivateKey()
        let keys = await JWTKeyCollection().addES512(key: ec, kid: "initial")

        let signature = try await keys.getKey(for: "initial").sign(message)

        let params = ec.parameters!
        try await keys.addES512(key: ES512PublicKey(parameters: params), kid: "params")
        try await XCTAssertTrueAsync(try await keys.getKey(for: "params").verify(signature, signs: message))
        XCTAssertEqual(ec.curve, .p521)
    }

    // MARK: X5C

    func testSigningWithX5CChain() async throws {
        let keyCollection = try await JWTKeyCollection().addES256(key: ES256PrivateKey(pem: x5cLeafCertKey))

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let token = try await keyCollection.sign(payload, x5c: x5cCerts)
        let parser = try JWTParser(token: token.bytes)

        let x5c = try XCTUnwrap(parser.header().x5c)
        let pemCerts = try x5c.map(getPEMString)
        XCTAssertEqual(pemCerts, x5cCerts)
        let verifier = try X5CVerifier(rootCertificates: [x5cCerts.last!])
        await XCTAssertNoThrowAsync(try await verifier.verifyJWS(token, as: TestPayload.self))
    }

    func testSigningWithInvalidX5CChain() async throws {
        let keyCollection = try await JWTKeyCollection().addES256(key: ES256PrivateKey(pem: x5cLeafCertKey))

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        // Remove the intermediate cert from the chain
        let certs = x5cCerts.enumerated().filter { $0.offset != 1 }.map { $0.element }

        let token = try await keyCollection.sign(payload, x5c: certs)
        let parser = try JWTParser(token: token.bytes)

        let x5c = try XCTUnwrap(parser.header().x5c)
        let pemCerts = try x5c.map(getPEMString)
        XCTAssertEqual(pemCerts, certs)
        let verifier = try X5CVerifier(rootCertificates: [certs.last!])
        await XCTAssertThrowsErrorAsync(try await verifier.verifyJWS(token, as: TestPayload.self))
    }

    // MARK: Claim

    func testExpirationEncoding() async throws {
        let exp = ExpirationClaim(value: Date(timeIntervalSince1970: 2_000_000_000))
        let keyCollection = await JWTKeyCollection().addHS256(key: "secret".bytes)
        let jwt = try await keyCollection.sign(ExpirationPayload(exp: exp))
        let parser = try JWTParser(token: jwt.bytes)
        try XCTAssertEqual(parser.header().typ, "JWT")
        try XCTAssertEqual(parser.header().alg, "HS256")
        try XCTAssertEqual(parser.payload(as: ExpirationPayload.self).exp, exp)
        try await parser.verify(using: keyCollection.getKey())
    }

    // MARK: Custom Header Fields

    func testCustomHeaderFields() async throws {
        let keyCollection = await JWTKeyCollection().addHS256(key: "secret".bytes)

        let customFields: [String: JWTHeaderField] = ["foo": .string("bar"), "baz": .int(42)]
        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let token = try await keyCollection.sign(payload, customFields: customFields)

        let parser = try JWTParser(token: token.bytes)
        let header = try parser.header()
        XCTAssertEqual(header.customFields, customFields)

        let encodedHeader = try JSONEncoder().encode(header)
        let jsonFields = """
        {
          "alg": "HS256",
          "typ": "JWT",
          "foo": "bar",
          "baz": 42
        }
        """
        XCTAssertEqual(
            try JSONDecoder().decode([String: JWTHeaderField].self, from: encodedHeader),
            try JSONDecoder().decode([String: JWTHeaderField].self, from: jsonFields.data(using: .utf8)!)
        )
    }

    func testSampleOpenbankingHeader() async throws {
        let keyCollection = await JWTKeyCollection().addHS256(key: "secret".bytes)

        // https://openbanking.atlassian.net/wiki/spaces/DZ/pages/937656404/Read+Write+Data+API+Specification+-+v3.1
        let customFields: [String: JWTHeaderField] = [
            "http://openbanking.org.uk/iat": .int(1_501_497_671),
            "http://openbanking.org.uk/iss": .string("C=UK, ST=England, L=London, O=Acme Ltd."),
            "http://openbanking.org.uk/tan": .string("openbanking.org.uk"),
            "crit": .array([.string("b64"), .string("http://openbanking.org.uk/iat"), .string("http://openbanking.org.uk/iss"), .string("http://openbanking.org.uk/tan")]),
        ]

        let kid: JWKIdentifier = "90210ABAD"
        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let token = try await keyCollection.sign(payload, kid: kid, customFields: customFields)

        let parser = try JWTParser(token: token.bytes)
        let header = try parser.header()
        XCTAssertEqual(header.customFields, customFields)
        XCTAssertEqual(header.kid, kid)
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

extension ECDSA.PublicKey: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.parameters?.x == rhs.parameters?.x && lhs.parameters?.y == rhs.parameters?.y
    }
}

extension ECDSA.PrivateKey: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.parameters?.x == rhs.parameters?.x && lhs.parameters?.y == rhs.parameters?.y
    }
}
