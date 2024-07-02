// snippet.KEY_COLLECTION
import JWTKit

// Signs and verifies JWTs
let keys = JWTKeyCollection()

// snippet.EXAMPLE_PAYLOAD
struct ExamplePayload: JWTPayload {
    var sub: SubjectClaim
    var exp: ExpirationClaim
    var admin: BoolClaim

    func verify(using key: some JWTAlgorithm) throws {
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
do
{
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

do
{
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

do
{
    // snippet.EDDSA
    // Initialize an EdDSA key with public PEM
    let publicKey = try EdDSA.PublicKey(x: "...", curve: .ed25519)

    // Initialize an EdDSA key with private PEM
    let privateKey = try EdDSA.PrivateKey(x: "...", d: "...", curve: .ed25519)

    // Add public key to the key collection
    await keys.add(eddsa: publicKey)

    // Add private key to the key collection
    await keys.add(eddsa: privateKey)
    // snippet.end
}

do
{
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
do
{
    // snippet.RSA_FROM_PEM
    let rsaPublicKey = "-----BEGIN PUBLIC KEY----- ... -----END PUBLIC KEY-----"

    // Initialize an RSA key with public PEM
    let key = try Insecure.RSA.PublicKey(pem: rsaPublicKey)

    // snippet.RSA_ADD
    // Add RSA with SHA-256 algorithm
    await keys.add(rsa: key, digestAlgorithm: .sha256)

    // Add RSA with SHA-256 and PSS padding algorithm
    await keys.add(pss: key, digestAlgorithm: .sha256)
    // snippet.end
}
