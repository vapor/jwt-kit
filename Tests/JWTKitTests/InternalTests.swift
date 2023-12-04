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
        let header: JWTHeader = .init(fields: ["x5c": .array(x5cCerts.map(JWTHeaderField.string))])
        let token = try await keyCollection.sign(payload, with: header)
        let parser = try JWTParser(token: token.bytes)

        let x5c = try XCTUnwrap(parser.header().x5c?.asArray(of: String.self))
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

        let header: JWTHeader = .init(fields: ["x5c": .array(certs.map(JWTHeaderField.string))])
        let token = try await keyCollection.sign(payload, with: header)
        let parser = try JWTParser(token: token.bytes)

        let x5c = try XCTUnwrap(parser.header().x5c?.asArray(of: String.self))
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
        let typ = try XCTUnwrap(parser.header().typ?.asString)
        XCTAssertEqual(typ, "JWT")
        let alg = try XCTUnwrap(parser.header().alg?.asString)
        XCTAssertEqual(alg, "HS256")
        try XCTAssertEqual(parser.payload(as: ExpirationPayload.self).exp, exp)
        try await parser.verify(using: keyCollection.getKey())
    }

    // MARK: Custom Header Fields

    func testCustomHeaderFields() async throws {
        let keyCollection = await JWTKeyCollection().addHS256(key: "secret".bytes)

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )
        let customFields: [String: JWTHeaderField] = ["foo": .string("bar"), "baz": .int(42)]
        let token = try await keyCollection.sign(payload, with: .init(fields: customFields))

        let parser = try JWTParser(token: token.bytes)
        let header = try parser.header()
        let foo = try XCTUnwrap(header.foo?.asString)
        let baz = try XCTUnwrap(header.baz?.asInt)
        XCTAssertEqual(foo, "bar")
        XCTAssertEqual(baz, 42)

        let encodedHeader = try JSONEncoder().encode(header)
        let jsonFields = """
        {
          "alg": "HS256",
          "typ": "JWT",
          "foo": "bar",
          "baz": 42
        }
        """

        let jsonDecoder = JSONDecoder()
        XCTAssertEqual(
            try jsonDecoder.decode([String: JWTHeaderField].self, from: encodedHeader),
            try jsonDecoder.decode([String: JWTHeaderField].self, from: jsonFields.data(using: .utf8)!)
        )
    }

    func testSampleOpenbankingHeader() async throws {
        let keyCollection = await JWTKeyCollection().addHS256(key: "secret".bytes)

        // https://openbanking.atlassian.net/wiki/spaces/DZ/pages/937656404/Read+Write+Data+API+Specification+-+v3.1
        let customFields: [String: JWTHeaderField] = [
            "kid": .string("90210ABAD"),
            "http://openbanking.org.uk/iat": .int(1_501_497_671),
            "http://openbanking.org.uk/iss": .string("C=UK, ST=England, L=London, O=Acme Ltd."),
            "http://openbanking.org.uk/tan": .string("openbanking.org.uk"),
            "crit": .array([
                .string("b64"),
                .string("http://openbanking.org.uk/iat"),
                .string("http://openbanking.org.uk/iss"),
                .string("http://openbanking.org.uk/tan")]
            ),
        ]

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let token = try await keyCollection.sign(payload, with: .init(fields: customFields))

        let parser = try JWTParser(token: token.bytes)
        let header = try parser.header()
        let iat = try header[dynamicMember: "http://openbanking.org.uk/iat"]?.asInt
        XCTAssertEqual(iat, 1_501_497_671)
        let iss = try header[dynamicMember: "http://openbanking.org.uk/iss"]?.asString
        XCTAssertEqual(iss, "C=UK, ST=England, L=London, O=Acme Ltd.")
        let tan = try header[dynamicMember: "http://openbanking.org.uk/tan"]?.asString
        XCTAssertEqual(tan, "openbanking.org.uk")
        let crit = try header.crit?.asArray(of: String.self)
        XCTAssertEqual(crit, ["b64", "http://openbanking.org.uk/iat", "http://openbanking.org.uk/iss", "http://openbanking.org.uk/tan"])
        XCTAssertEqual(try parser.header().kid?.asString, "90210ABAD")
    }

    func testCustomObjectHeader() async throws {
        let keyCollection = await JWTKeyCollection().addHS256(key: "secret".bytes)

        let customFields: [String: JWTHeaderField] = [
            "kid": .string("some-kid"),
            "foo": .object(["bar": .string("baz")]),
        ]

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let token = try await keyCollection.sign(payload, with: .init(fields: customFields))

        let parser = try JWTParser(token: token.bytes)
        let header = try parser.header()
        let foo = try header.foo?.asObject(of: String.self)
        XCTAssertEqual(foo, ["bar": "baz"])
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
