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

The table below shows a list of PostgresNIO major releases alongside their compatible Swift versions. 

|Version|Swift|SPM|
|---|---|---|---|
|4.0|5.2+|`from: "4.0.0"`|

Use the SPM string to easily include the dependendency in your `Package.swift` file.

```swift
.package(url: "https://github.com/vapor/mysql-nio.git", from: ...)
```

### Supported Platforms

JWTKit supports the following platforms:

- Ubuntu 16.04, 18.04, 20.04
- macOS 10.15, 11
- CentOS 8
- Amazon Linux 2

## Overview

JWTKit provides APIs for signing and verifying JSON Web Tokens. It supports the following features:

- Signing
- Verifying
- RSA (RS256, RS384, RS512)
- ECDSA (ES256, ES384, ES512)
- HMAC (HS256, HS384, HS512)
- Claims (aud, exp, iss, etc)
- JSON Web Keys (JWKs)

This package ships a private copy of BoringSSL for cryptography.

## Vapor

If you are using Vapor, check out the [JWT](https://github.com/vapor/jwt) package which makes it easier to configure and use JWTKit in your project.

## Getting Started

To start verifying or signing JWT tokens, you will need an instance of `JWTSigners`. 

```swift
import JWTKit

let signers = JWTSigners()
```

Let's add a simple HS256 signer for testing. HMAC signers can sign _and_ verify tokens. 

```swift
// Add HMAC with SHA-256 signer.
signers.use(.hs256(key: "secret"))
```

For this example, we'll use the very secure key `"secret"`. 

### Verifying

Let's try to verify the following example JWT.

```
let jwt = """
eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ2YXBvciIsImV4cCI6NjQwOTIyMTEyMDAsImFkbWluIjp0cnVlfQ.lS5lpwfRNSZDvpGQk6x5JI1g40gkYCOWqbc3J_ghowo
"""
```

You can inspect the contents of this token by visiting [jwt.io](https://jwt.io) and pasting the token in the debugger. 

We need to create a struct conforming to `JWTPayload` that represents the JWT's structure.

```swift
// JWT payload structure.
struct TestPayload: JWTPayload, Equatable {
    // Maps the longer Swift property names to the
    // shortened keys used in the JWT payload.
    enum CodingKeys: String, CodingKey {
        case subject = "sub"
        case expiration = "exp"
        case admin
    }

    // The "sub" (subject) claim identifies the principal that is the
    // subject of the JWT.
    var subject: SubjectClaim

    // The "exp" (expiration time) claim identifies the expiration time on
    // or after which the JWT MUST NOT be accepted for processing.
    var expiration: ExpirationClaim

    // Custom data.
    // If true, the user is an admin.
    var admin: Bool

    // Run any necessary verification logic here.
    //
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
    admin: true
)
```

### Signing

We can also _generate_ JWTs, also known as signing. To demonstrate this, let's use the `TestPayload` from the previous section. 

```swift
// Create a new instance of our JWTPayload
let payload = TestPayload(
    subject: .init(value: "vapor"),
    expiration: .init(value: .distantFuture),
    admin: true
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

## RSA

## ECDSA

## HMAC

## Claims

<hr>

**Originally authored by** [@siemensikkema](http://github.com/siemensikkema)  
