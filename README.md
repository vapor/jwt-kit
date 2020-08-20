<img 
    src="https://user-images.githubusercontent.com/1342803/59471117-1c77b300-8e08-11e9-838e-441b280855b3.png" 
    height="64" 
    alt="JWTKit"
/>


<a href="https://docs.vapor.codes/4.0/">
    <img src="http://img.shields.io/badge/read_the-docs-2196f3.svg" alt="Documentation">
</a>
<a href="https://discord.gg/vapor">
    <img src="https://img.shields.io/discord/431917998102675485.svg" alt="Team Chat">
</a>
<a href="LICENSE">
    <img src="http://img.shields.io/badge/license-MIT-brightgreen.svg" alt="MIT License">
</a>
<a href="https://github.com/vapor/jwt-kit/actions">
    <img src="https://github.com/vapor/jwt-kit/workflows/test/badge.svg" alt="Continuous Integration">
</a>
<a href="https://swift.org">
    <img src="http://img.shields.io/badge/swift-5.2-brightgreen.svg" alt="Swift 5.2">
</a>
<br>
<br>

🔑 JSON Web Token signing and verification (HMAC, RSA, ECDSA) using BoringSSL.

### Major Releases

The table below shows a list of JWTKit major releases alongside their compatible Swift versions. 

|Version|Swift|SPM|
|---|---|---|
|4.0|5.2+|`from: "4.0.0"`|
|3.0|4.0+|`from: "3.0.0"`|
|2.0|3.1+|`from: "2.0.0"`|
|1.0|3.1+|`from: "1.0.0"`|

Use the SPM string to easily include the dependendency in your `Package.swift` file.

```swift
.package(url: "https://github.com/vapor/jwt-kit.git", from: "4.0.0")
```

> Note: Prior to version 4.0, this package was included in `vapor/jwt.git`. 

### Supported Platforms

JWTKit supports the following platforms:

- Ubuntu 16.04, 18.04, 20.04
- macOS 10.15, 11
- CentOS 8
- Amazon Linux 2

## Overview

JWTKit provides APIs for signing and verifying JSON Web Tokens ([RFC7519](https://tools.ietf.org/html/rfc7519)). It supports the following features:

- Verifying (parsing)
- Signing (serializing)
- RSA (RS256, RS384, RS512)
- ECDSA (ES256, ES384, ES512)
- HMAC (HS256, HS384, HS512)
- Claims (aud, exp, iss, etc)
- JSON Web Keys (JWK, JWKS)

This package ships a private copy of BoringSSL for cryptography.

## Vapor

If you are using Vapor, check out the [JWT](https://github.com/vapor/jwt) package which makes it easier to configure and use JWTKit in your project.

## Getting Started

To start verifying or signing JWT tokens, you will need an instance of `JWTSigners`. 

```swift
import JWTKit

// Signs and verifies JWTs
let signers = JWTSigners()
```

Let's add a simple HS256 signer for testing. HMAC signers can sign _and_ verify tokens. 

```swift
// Add HMAC with SHA-256 signer.
signers.use(.hs256(key: "secret"))
```

For this example, we'll use the very secure key _secret_. 

### Verifying

Let's try to verify the following example JWT.

```swift
let jwt = """
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YXBvciIsImV4cCI6NjQwOTIyMTEyMDAsImFkbWluIjp0cnVlfQ.lS5lpwfRNSZDvpGQk6x5JI1g40gkYCOWqbc3J_ghowo
"""
```

You can inspect the contents of this token by visiting [jwt.io](https://jwt.io) and pasting the token in the debugger. Set the key in the "Verify Signature" section to `secret`. 

We need to create a struct conforming to `JWTPayload` that represents the JWT's structure. We'll use JWTKit's included [claims](#claims) to handle common fields like `sub` and `exp`. 

```swift
// JWT payload structure.
struct TestPayload: JWTPayload, Equatable {
    // Maps the longer Swift property names to the
    // shortened keys used in the JWT payload.
    enum CodingKeys: String, CodingKey {
        case subject = "sub"
        case expiration = "exp"
        case isAdmin = "admin"
    }

    // The "sub" (subject) claim identifies the principal that is the
    // subject of the JWT.
    var subject: SubjectClaim

    // The "exp" (expiration time) claim identifies the expiration time on
    // or after which the JWT MUST NOT be accepted for processing.
    var expiration: ExpirationClaim

    // Custom data.
    // If true, the user is an admin.
    var isAdmin: Bool

    // Run any additional verification logic beyond
    // signature verification here.
    // Since we have an ExpirationClaim, we will
    // call its verify method.
    func verify(using signer: JWTSigner) throws {
        try self.expiration.verifyNotExpired()
    }
}
```

Now that we have a `JWTPayload`, we can use `JWTSigners` to parse and verify the JWT.

```swift
// Parses the JWT and verifies its signature.
let payload = try signers.verify(jwt, as: TestPayload.self)
print(payload)
```

If everything worked, you should see the payload printed:

```swift
TestPayload(
    subject: "vapor", 
    expiration: 4001-01-01 00:00:00 +0000, 
    isAdmin: true
)
```

### Signing

We can also _generate_ JWTs, also known as signing. To demonstrate this, let's use the `TestPayload` from the previous section. 

```swift
// Create a new instance of our JWTPayload
let payload = TestPayload(
    subject: "vapor",
    expiration: .init(value: .distantFuture),
    isAdmin: true
)
```

Then, pass the payload to `JWTSigners.sign`. 

```swift
// Sign the payload, returning a JWT.
let jwt = try signers.sign(payload)
print(jwt)
```

You should see a JWT printed. This can be fed back into the `verify` method to access the payload.

## JWK

A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key ([RFC7517](https://tools.ietf.org/html/rfc7517)). These are commonly used to supply clients with keys for verifying JWTs.

For example, Apple hosts their _Sign in with Apple_ JWKS at the following URL.

```http
GET https://appleid.apple.com/auth/keys
```

You can add this JSON Web Key Set (JWKS) to your `JWTSigners`. 

```swift
import Foundation
import JWTKit

// Download the JWKS.
// This could be done asynchronously if needed.
let jwksData = try Data(
    contentsOf: URL(string: "https://appleid.apple.com/auth/keys")!
)

// Decode the downloaded JSON.
let jwks = try JSONDecoder().decode(JWKS.self, from: jwksData)

// Create signers and add JWKS.
let signers = JWTSigners()
try signers.use(jwks: jwks)
```

You can now pass JWTs from Apple to the `verify` method. The key identifier (`kid`) in the JWT header will be used to automatically select the correct key for verification.

> Note: As of writing, JWK only supports RSA keys.

## HMAC

HMAC is the simplest JWT signing algorithm. It uses a single key that can both sign and verify tokens. The key can be any length.

- `hs256`: HMAC with SHA-256
- `hs384`: HMAC with SHA-384
- `hs512`: HMAC with SHA-512

```swift
// Add HMAC with SHA-256 signer.
signers.use(.hs256(key: "secret"))
```

## RSA

RSA is the most commonly used JWT signing algorithm. It supports distinct public and private keys. This means that a public key can be distributed for verifying JWTs are authentic while the private key that generates them is kept secret.

To create an RSA signer, first initialize an `RSAKey`. This can be done by passing in the components.

```swift
// Initialize an RSA key with components.
let key = RSAKey(
    modulus: "...",
    exponent: "...",
    // Only included in private keys.
    privateExponent: "..."
)
```

You can also choose to load a PEM file:

```swift
let rsaPublicKey = """
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
PmjXpbCkecAWLj/CcDWEcuTZkYDiSG0zgglbbbhcV0vJQDWSv60tnlA3cjSYutAv
7FPo5Cq8FkvrdDzeacwRSxYuIq1LtYnd6I30qNaNthntjvbqyMmBulJ1mzLI+Xg/
aX4rbSL49Z3dAQn8vQIDAQAB
-----END PUBLIC KEY-----
"""

// Initialize an RSA key with public pem.
let key = RSAKey.public(pem: rsaPublicKey)
```

Use `.private` for loading private RSA pem keys. These start with:

```
-----BEGIN RSA PRIVATE KEY-----
```

Use `.certificate` for loading X.509 certificates. These start with:

```
-----BEGIN CERTIFICATE-----
```

Once you have the RSAKey, you can use it to create an RSA signer.

- `rs256`: RSA with SHA-256
- `rs384`: RSA with SHA-384
- `rs512`: RSA with SHA-512

```swift
// Add RSA with SHA-256 signer.
try signers.use(.rs256(key: .public(pem: rsaPublicKey)))
```

## ECDSA

ECDSA is a more modern algorithm that is similar to RSA. It is considered to be more secure for a given key length than RSA<sup>[1](#1)</sup>. However, you should do your own research before deciding. 

Like RSA, you can load ECDSA keys using PEM files: 

```swift
let ecdsaPublicKey = """
-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoZIzj0DAQcDQgAE2adMrdG7aUfZH57aeKFFM01dPnkx
C18ScRb4Z6poMBgJtYlVtd9ly63URv57ZW0Ncs1LiZB7WATb3svu+1c7HQ==
-----END PUBLIC KEY-----
"""

// Initialize an ECDSA key with public pem.
let key = ECDSAKey.public(pem: ecdsaPublicKey)
```

Use `.private` for loading private ECDSA pem keys. These start with:

```
-----BEGIN PRIVATE KEY-----
```

Once you have the ECDSAKey, you can use it to create an ECDSA signer.

- `es256`: ECDSA with SHA-256
- `es384`: ECDSA with SHA-384
- `es512`: ECDSA with SHA-512

```swift
// Add ECDSA with SHA-256 signer.
try signers.use(.es256(key: .public(pem: ecdsaPublicKey)))
```

## Claims

JWTKit includes several helpers for implementing common [JWT claims](https://tools.ietf.org/html/rfc7519#section-4.1). 

|Claim|Type|Verify Method|
|---|---|---|
|`aud`|`AudienceClaim`|`verifyIntendedAudience(includes:)`|
|`exp`|`ExpirationClaim`|`verifyNotExpired(currentDate:)`|
|`jti`|`IDClaim`|n/a|
|`iat`|`IssuedAtClaim`|n/a|
|`iss`|`IssuerClaim`|n/a|
|`locale`|`LocaleClaim`|n/a|
|`nbf`|`NotBeforeClaim`|`verifyNotBefore(currentDate:)`|
|`sub`|`SubjectClaim`|n/a|

All claims should be verified in the `JWTPayload.verify` method. If the claim has a special verify method, you can use that. Otherwise, access the value of the claim using `value` and check that it is valid.

---

This package was originally authored by the wonderful [@siemensikkema](http://github.com/siemensikkema).

---

<a name="1">1</a>: [https://sectigostore.com/blog/ecdsa-vs-rsa-everything-you-need-to-know/](https://sectigostore.com/blog/ecdsa-vs-rsa-everything-you-need-to-know/)
