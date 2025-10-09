// snippet.KEY_COLLECTION
import JWTKit

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

// Signs and verifies JWTs
let keys = JWTKeyCollection()

// snippet.EXAMPLE_PAYLOAD
struct ExamplePayload: JWTPayload {
    var sub: SubjectClaim
    var exp: ExpirationClaim
    var admin: BoolClaim

    func verify(using _: some JWTAlgorithm) throws {
        try self.exp.verifyNotExpired()
    }
}

// snippet.KEY_COLLECTION_ADD_HS256
// Registers an HS256 (HMAC-SHA-256) signer.
await keys.add(hmac: "secret", digestAlgorithm: .sha256)

// snippet.KEY_COLLECTION_ADD_HS256_KID
// Registers an HS256 (HMAC-SHA-256) signer with a key identifier.
await keys.add(hmac: "secret", digestAlgorithm: .sha256, kid: "my-key")

// snippet.KEY_COLLECTION_CREATE_ES256
let ecdsaPublicKey = "-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----"

// Initialize an ECDSA key with public pem.
let key = try ES256PublicKey(pem: ecdsaPublicKey)

// snippet.KEY_COLLECTION_ADD_ES256
await keys.add(ecdsa: key)

// snippet.end
do {
    // Create a new instance of our JWTPayload
    let payload = ExamplePayload(
        sub: "vapor",
        exp: .init(value: .distantFuture),
        admin: true
    )

    // snippet.EXAMPLE_PAYLOAD_SIGN
    // Sign the payload, returning the JWT as String
    let jwt = try await keys.sign(payload, header: ["kid": "my-key"])
    print(jwt)
    // snippet.end
}

do {
    // snippet.VERIFYING
    let exampleJWT = """
        eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YXBvciIsImV4cCI6NjQwOTIyMTEyMDAsImFkbWluIjp0cnVlfQ.lS5lpwfRNSZDvpGQk6x5JI1g40gkYCOWqbc3J_ghowo
        """

    // snippet.VERIFYING_PAYLOAD
    // Parse the JWT, verifies its signature, and decodes its content
    let payload = try await keys.verify(exampleJWT, as: ExamplePayload.self)
    print(payload)
    // snippet.end
}

do {
    // snippet.EDDSA
    // Initialize an EdDSA key with public PEM
    let publicKey = try EdDSA.PublicKey(x: "...", curve: .ed25519)

    // Initialize an EdDSA key with private PEM
    let privateKey = try EdDSA.PrivateKey(d: "...", curve: .ed25519)

    // Add public key to the key collection
    await keys.add(eddsa: publicKey)

    // Add private key to the key collection
    await keys.add(eddsa: privateKey)
    // snippet.end
}

do {
    // snippet.RSA
    // Initialize an RSA key with components.
    let key = try Insecure.RSA.PrivateKey(
        modulus: "...",
        exponent: "...",
        privateExponent: "..."
    )
    // snippet.end
    _ = key
}

do {
    // snippet.RSA_FROM_PEM
    let rsaPublicKey = "-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----"

    // Initialize an RSA key with public PEM
    let key = try Insecure.RSA.PublicKey(pem: rsaPublicKey)

    // snippet.RSA_ADD
    // Add RSA with SHA-256 algorithm
    await keys.add(rsa: key, digestAlgorithm: .sha256)

    // Add RSA with SHA-512 and PSS padding algorithm
    await keys.add(pss: key, digestAlgorithm: .sha512)
    // snippet.end
}

extension DataProtocol {
    func base64URLDecodedBytes() -> [UInt8] {
        let string = String(decoding: self, as: UTF8.self)
            .replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")
        let padding = string.count % 4 == 0 ? "" : String(repeating: "=", count: 4 - string.count % 4)
        return [UInt8](Data(base64Encoded: string + padding) ?? Data())
    }

    func base64URLEncodedBytes() -> [UInt8] {
        Data(self).base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
            .utf8
            .map { UInt8($0) }
    }
}

// snippet.CUSTOM_SERIALIZER
struct CustomSerializer: JWTSerializer {
    var jsonEncoder: JWTJSONEncoder = .defaultForJWT

    func serialize(_ payload: some JWTPayload, header: JWTHeader) throws -> Data {
        if header.b64?.asBool == true {
            try Data(self.jsonEncoder.encode(payload).base64URLEncodedBytes())
        } else {
            try self.jsonEncoder.encode(payload)
        }
    }
}

struct CustomParser: JWTParser {
    var jsonDecoder: JWTJSONDecoder = .defaultForJWT

    func parse<Payload>(_ token: some DataProtocol, as _: Payload.Type) throws -> (
        header: JWTHeader, payload: Payload, signature: Data
    ) where Payload: JWTPayload {
        let (encodedHeader, encodedPayload, encodedSignature) = try getTokenParts(token)

        let header = try jsonDecoder.decode(
            JWTHeader.self, from: .init(encodedHeader.base64URLDecodedBytes()))

        let payload =
            if header.b64?.asBool ?? true {
                try self.jsonDecoder.decode(Payload.self, from: .init(encodedPayload.base64URLDecodedBytes()))
            } else {
                try self.jsonDecoder.decode(Payload.self, from: .init(encodedPayload))
            }

        let signature = Data(encodedSignature.base64URLDecodedBytes())

        return (header: header, payload: payload, signature: signature)
    }
}

// snippet.end

do {
    // snippet.CUSTOM_SIGNING
    let keyCollection = await JWTKeyCollection()
        .add(hmac: "secret", digestAlgorithm: .sha256, parser: CustomParser(), serializer: CustomSerializer())

    let payload = ExamplePayload(sub: "vapor", exp: .init(value: .init(timeIntervalSince1970: 2_000_000_000)), admin: false)

    let token = try await keyCollection.sign(payload, header: ["b64": true])
    // snippet.end
    _ = token
}

do {
    // snippet.CUSTOM_ENCODING
    let encoder = JSONEncoder()
    encoder.dateEncodingStrategy = .iso8601
    let decoder = JSONDecoder()
    decoder.dateDecodingStrategy = .iso8601

    let parser = DefaultJWTParser(jsonDecoder: decoder)
    let serializer = DefaultJWTSerializer(jsonEncoder: encoder)

    let keyCollection = await JWTKeyCollection()
        .add(hmac: "secret", digestAlgorithm: .sha256, parser: parser, serializer: serializer)
    // snippet.end
    _ = keyCollection
}
