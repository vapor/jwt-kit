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
        let header: JWTHeader = ["x5c": .array(x5cCerts.map(JWTHeaderField.string))]
        let token = try await keyCollection.sign(payload, header: header)
        let parsed = try DefaultJWTParser().parse(token.bytes, as: TestPayload.self)

        let x5c = try XCTUnwrap(parsed.header.x5c)
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

        let header: JWTHeader = ["x5c": .array(certs.map(JWTHeaderField.string))]
        let token = try await keyCollection.sign(payload, header: header)
        let parsed = try DefaultJWTParser().parse(token.bytes, as: TestPayload.self)

        let x5c = try XCTUnwrap(parsed.header.x5c)
        let pemCerts = try x5c.map(getPEMString)
        XCTAssertEqual(pemCerts, certs)
        let verifier = try X5CVerifier(rootCertificates: [certs.last!])
        await XCTAssertThrowsErrorAsync(try await verifier.verifyJWS(token, as: TestPayload.self))
    }

    // MARK: Claim

    func testExpirationEncoding() async throws {
        let exp = ExpirationClaim(value: Date(timeIntervalSince1970: 2_000_000_000))
        let parser = DefaultJWTParser()
        let keyCollection = await JWTKeyCollection().addHS256(key: "secret".bytes, parser: parser)
        let jwt = try await keyCollection.sign(ExpirationPayload(exp: exp))
        let parsed = try parser.parse(jwt.bytes, as: ExpirationPayload.self)
        let header = parsed.header
        let typ = try XCTUnwrap(header.typ)
        XCTAssertEqual(typ, "JWT")
        let alg = try XCTUnwrap(header.alg)
        XCTAssertEqual(alg, "HS256")
        XCTAssertEqual(parsed.payload.exp, exp)
        _ = try await keyCollection.verify(jwt, as: ExpirationPayload.self)
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
        let customFields: JWTHeader = ["foo": "bar", "baz": 42]
        let token = try await keyCollection.sign(payload, header: customFields)

        let parsed = try DefaultJWTParser().parse(token.bytes, as: TestPayload.self)
        let foo = try XCTUnwrap(parsed.header.foo?.asString)
        let baz = try XCTUnwrap(parsed.header.baz?.asInt)
        XCTAssertEqual(foo, "bar")
        XCTAssertEqual(baz, 42)

        let encodedHeader = try JSONEncoder().encode(parsed.header)
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
        let customFields: JWTHeader = [
            "kid": "90210ABAD",
            "http://openbanking.org.uk/iat": 1_501_497_671,
            "http://openbanking.org.uk/iss": "C=UK, ST=England, L=London, O=Acme Ltd.",
            "http://openbanking.org.uk/tan": "openbanking.org.uk",
            "crit": [
                "b64",
                "http://openbanking.org.uk/iat",
                "http://openbanking.org.uk/iss",
                "http://openbanking.org.uk/tan",
            ],
        ]

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let token = try await keyCollection.sign(payload, header: customFields)

        let parsed = try DefaultJWTParser().parse(token.bytes, as: TestPayload.self)
        let iat = parsed.header[dynamicMember: "http://openbanking.org.uk/iat"]?.asInt
        XCTAssertEqual(iat, 1_501_497_671)
        let iss = parsed.header[dynamicMember: "http://openbanking.org.uk/iss"]?.asString
        XCTAssertEqual(iss, "C=UK, ST=England, L=London, O=Acme Ltd.")
        let tan = parsed.header[dynamicMember: "http://openbanking.org.uk/tan"]?.asString
        XCTAssertEqual(tan, "openbanking.org.uk")
        XCTAssertEqual(parsed.header.crit, ["b64", "http://openbanking.org.uk/iat", "http://openbanking.org.uk/iss", "http://openbanking.org.uk/tan"])
        XCTAssertEqual(parsed.header.kid, "90210ABAD")
    }

    func testCustomObjectHeader() async throws {
        let keyCollection = await JWTKeyCollection().addHS256(key: "secret".bytes)

        let customFields: JWTHeader = [
            "kid": "some-kid",
            "foo": ["bar": "baz"],
        ]

        let payload = TestPayload(
            sub: "vapor",
            name: "Foo",
            admin: false,
            exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000))
        )

        let token = try await keyCollection.sign(payload, header: customFields)

        let parsed = try DefaultJWTParser().parse(token.bytes, as: TestPayload.self)
        let foo = try parsed.header.foo?.asObject(of: String.self)
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

    let publicKey = """
    -----BEGIN PUBLIC KEY-----
    MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAy/FtQ/cOcx6ZgyaqU54C
    ESfkpttXuNnEZ07nYXXo8ylIiUFpB0r0Fecgv/tIhF1LFCWBHUsqyoSRQz0/iBRn
    YyIsG+yF/q1K3ll5Q/2GAS9/28jBuJGKDuKIj6dgPlr33si6bjeePTl4ZO6OZFxG
    Yyn4x035pwGwjKGFuQRKYh0AtxwHiWeRIsAJ/B2Z+VGOpcSXH+x/YUfN8Q9FuyGU
    zcsVLuGizbooRSMSSoD/y/8veWOnXWbMsh0KKTON/+yTmAcLn2tOzFmsYgHQXatW
    0f2XjrdmmWl4VfiekFKFDvGenxum9nEJrzIJOMm6qHnIiyCNA3xbMqmr7oqeIUa+
    fQIDAQAB
    -----END PUBLIC KEY-----
    """
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
