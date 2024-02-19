<p align="center">
<picture>
  <source media="(prefers-color-scheme: dark)" srcset="https://github.com/vapor/jwt-kit/assets/1130717/06939767-8779-42ea-9bb6-9d3e7a07d20c">
  <source media="(prefers-color-scheme: light)" srcset="https://github.com/vapor/jwt-kit/assets/1130717/bdc5befe-01c4-4e50-a203-c6ef71e16394">
  <img src="https://github.com/vapor/jwt-kit/assets/1130717/bdc5befe-01c4-4e50-a203-c6ef71e16394" height="96" alt="JWTKit">
</picture> 
<br>
<br>
<a href="https://docs.vapor.codes/4.0/"><img src="https://design.vapor.codes/images/readthedocs.svg" alt="Documentation"></a>
<a href="https://discord.gg/vapor"><img src="https://design.vapor.codes/images/discordchat.svg" alt="Team Chat"></a>
<a href="LICENSE"><img src="https://design.vapor.codes/images/mitlicense.svg" alt="MIT License"></a>
<a href="https://github.com/vapor/jwt-kit/actions/workflows/test.yml"><img src="https://img.shields.io/github/actions/workflow/status/vapor/jwt-kit/test.yml?event=push&style=plastic&logo=github&label=tests&logoColor=%23ccc" alt="Continuous Integration"></a>
<a href="https://codecov.io/github/vapor/jwt-kit"><img src="https://img.shields.io/codecov/c/github/vapor/jwt-kit?style=plastic&logo=codecov&label=codecov"></a>
</p>

<br>
</p>

<br>

🔑 JSON Web Token signing and verification (HMAC, RSA, ECDSA, EdDSA) using SwiftCrypto and BoringSSL.

### Major Releases

The table below shows a list of JWTKit major releases alongside their compatible Swift versions. 

|Version|Swift|SPM|
|---|---|---|
|4.0|5.6+|`from: "4.0.0"`|

Use the SPM string to easily include the dependendency in your `Package.swift` file.

```swift
.package(url: "https://github.com/vapor/jwt-kit.git", from: "4.0.0")
```

> Note: Prior to version 4.0, this package was part of [vapor/jwt](https://github.com/vapor/jwt). 

### Supported Platforms

JWTKit supports all platforms supported by Swift 5.6 and later, with the exception of Windows.

## Overview

JWTKit provides APIs for signing and verifying JSON Web Tokens, as specified by [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html). The following features are supported:

- Parsing
- Signature verification
- Payload signing
- Serialization
- Claim validation (`aud`, `exp`, `jti`, `iss`, `iat`, `nbf`, `sub`, and custom claims)
- JSON Web Keys (`JWK`, `JWKS`)

 The following algorithms, as defined in [RFC 7518 § 3](https://www.rfc-editor.org/rfc/rfc7518.html#section-3) and [RFC 8037 § 3](https://www.rfc-editor.org/rfc/rfc8037.html#section-3), are supported for both signing and verification:

- HS256, HS384, HS512 (HMAC with SHA-2)
- RS256, RS384, RS512 (RSA with SHA-2)
- ES256, ES384, ES512 (ECDSA with SHA-2)
- EdDSA
- none (unsigned)

For those algorithms which specify a curve type (`crv`), the following curves, as defined in [RFC 7518 § 6](https://www.rfc-editor.org/rfc/rfc7518.html#section-6) and [RFC 8037 § 3](https://www.rfc-editor.org/rfc/rfc8037.html#section-3), are supported:

- P-256 (ES256 algorithm only)
- P-384 (ES384 algorithm only)
- P-521 (ES512 algorithm only)
- Ed25519 (EdDSA algorithm only)

This package includes a vendored internal-only copy of [BoringSSL](https://boringssl.googlesource.com), used for certain cryptographic operations not currently available via [SwiftCrypto](https://github.com/apple/swift-crypto).

> Note: The `P-521` elliptic curve used with the ES512 signing algorithm is often assumed to be a typo, but confusingly, it is not. 

## Vapor

The [vapor/jwt](https://github.com/vapor/jwt) package provides first-class integration with Vapor and is recommended for all Vapor projects which want to use JWTKit.

## Getting Started

A `JWTSigners` object is used to load signing keys and keysets, and to sign and verify tokens: 

```swift
import JWTKit

// Signs and verifies JWTs
let signers = JWTSigners()
```

The `JWTSigner` class encapsulates a signature algorithm and an appropriate signing key. To use a signer, register it with the `JWTSigners` object:

```swift
// Registers a HS256 (HMAC-SHA-256) signer.
signers.use(.hs256(key: "secret"))
```

This example uses the _very_ secure key `"secret"`.

### Verifying

Let's try to verify the following example JWT:

```swift
let exampleJWT = """
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YXBvciIsImV4cCI6NjQwOTIyMTEyMDAsImFkbWluIjp0cnVlfQ.lS5lpwfRNSZDvpGQk6x5JI1g40gkYCOWqbc3J_ghowo
"""
```

You can inspect the contents of this token by visiting [jwt.io](https://jwt.io) and pasting the token in the debugger. Set the key in the "Verify Signature" section to `secret`. 

To verify a token, the format of the payload must be known. This is accomplished by defining a type conforming to the `JWTPayload` protocol. Each property of the payload type corresponds to a claim in the token. JWTKit provides predefined types for all of the claims specified by RFC 7519, as well as some convenience types for working with custom claims. For the example token, the payload looks like this:

```swift
struct ExamplePayload: JWTPayload {
    var sub: SubjectClaim
    var exp: ExpirationClaim
    var admin: BoolClaim

    func verify(using signer: JWTSigner) throws {
        try self.exp.verifyNotExpired()
    }
}
```

Using this payload, the `JWTSigners` object can process and verify the example JWT, returning its payload on success:

```swift
// Parses the JWT, verifies its signature, and decodes its content.
let payload = try signers.verify(exampleJWT, as: ExamplePayload.self)
print(payload)
```

If all works correctly, this code will print something like this:

```swift
TestPayload(
    sub: SubjectClaim(value: "vapor"),
    exp: ExpirationClaim(value: 4001-01-01 00:00:00 +0000),
    admin: BoolClaim(value: true)
)
```

> Note: The `admin` property of the example payload did not have to use the `BoolClaim` type; a simple `Bool` would have worked as well. The `BoolClaim` type is provided by JWTKit for convenience in working with the many JWT implementations which encode boolean values as JSON strings (e.g. `"true"` and `"false"`) rather than using JSON's `true` and `false` keywords.   

### Signing

We can also _generate_ JWTs, also known as signing. To demonstrate this, let's use the `TestPayload` from the previous section. 

```swift
// Create a new instance of our JWTPayload
let payload = ExamplePayload(
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

A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key, defined in [RFC7517](https://www.rfc-editor.org/rfc/rfc7517.html). These are commonly used to supply clients with keys for verifying JWTs. For example, Apple hosts their _Sign in with Apple_ JWKS at the URL `https://appleid.apple.com/auth/keys`.

You can add this JSON Web Key Set (JWKS) to your `JWTSigners`: 

```swift
import Foundation
import JWTKit

// Download the JWKS.
// This could be done asynchronously if needed.
let jwksData = try String(
    contentsOf: URL(string: "https://appleid.apple.com/auth/keys")!
)

// Create signers and add JWKS.
let signers = JWTSigners()
try signers.use(jwksJSON: jwksData)
```

You can now pass JWTs from Apple to the `verify` method. The key identifier (`kid`) in the JWT header will be used to automatically select the correct key for verification. A JWKS may contain any of the key types supported by JWTKit.  

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

To create an RSA signer, first initialize an `RSAKey`. This can be done by passing in the components:

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

Once you have the RSAKey, you can use it to create an RSA signer:

- `rs256`: RSA with SHA-256
- `rs384`: RSA with SHA-384
- `rs512`: RSA with SHA-512

```swift
// Add RSA with SHA-256 signer.
try signers.use(.rs256(key: .public(pem: rsaPublicKey)))
```

> Important: RSA, despite still being the common algorithm in use, is no longer recommended for new applications. If possible, use EdDSA or ECDSA instead.

## ECDSA

ECDSA is a more modern algorithm that is similar to RSA. It is considered to be more secure for a given key length than RSA. [Infosec Insights' June 2020 blog post "ECDSA vs RSA: Everything You Need to Know"](https://sectigostore.com/blog/ecdsa-vs-rsa-everything-you-need-to-know/) provides a detailed discussion on the differences between the two.

> IMPORTANT: Cryptography is a complex topic, and the decision of algorithm can directly impact the integrity, security, and privacy of your data. This README does not attempt to offer a meaningful discussion of these concerns; the package authors recommend doing your own research before making a final decision.

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

Once you have the ECDSAKey, you can use it to create an ECDSA signer:

- `es256`: ECDSA with SHA-256 and P-256
- `es384`: ECDSA with SHA-384 and P-384
- `es512`: ECDSA with SHA-512 and P-521

```swift
// Add ECDSA with SHA-256 signer.
try signers.use(.es256(key: .public(pem: ecdsaPublicKey)))
```

## Claims

JWTKit includes several helpers for implementing the "standard" JWT claims defined by [RFC § 4.1](https://www.rfc-editor.org/rfc/rfc7519.html#section-4.1): 

|Claim|Type|Verify Method|
|---|---|---|
|`aud`|`AudienceClaim`|`verifyIntendedAudience(includes:)`|
|`exp`|`ExpirationClaim`|`verifyNotExpired(currentDate:)`|
|`jti`|`IDClaim`|n/a|
|`iat`|`IssuedAtClaim`|n/a|
|`iss`|`IssuerClaim`|n/a|
|`nbf`|`NotBeforeClaim`|`verifyNotBefore(currentDate:)`|
|`sub`|`SubjectClaim`|n/a|

Whenever possible, all of a payload's claims should be verified in the `verify(using:)` method; those which do not have verification methods of their own may be verified manually.

Additional helpers are provided for common types of claims not defined by the RFC:

- `BoolClaim`: May be used for any claim whose value is a boolean flag. Will recognize both boolean JSON values and the strings `"true"` and `"false"`.
- `GoogleHostedDomainClaim`: For use with the `GoogleIdentityToken` vendor token type.
- `JWTMultiValueClaim`: A protocol for claims, such as `AudienceClaim` which can optionally be encoded as an array with multiple values.
- `JWTUnixEpochClaim`: A protocol for claims, such as `ExpirationClaim` and `IssuedAtClaim`, whose value is a count of seconds since the UNIX epoch (midnight of January 1, 1970).
- `LocaleClaim`: A claim whose value is a [BCP 47](https://www.rfc-editor.org/info/bcp47) language tag. Also used by `GoogleIdentityToken`.

---

_This package was originally authored by the wonderful [@siemensikkema](https://github.com/siemensikkema)._
