# ``JWTKit``

@Metadata {
    @TitleHeading(Package)
}

🔑 JSON Web Token signing and verification (HMAC, RSA, PSS, ECDSA, EdDSA) using SwiftCrypto.

Use the SPM string to easily include the dependendency in your `Package.swift` file

```swift
.package(url: "https://github.com/vapor/jwt-kit.git", from: "5.0.0")
```

and add it to your target's dependencies:

```swift
.product(name: "JWTKit", package: "jwt-kit")
```

### Supported Platforms

JWTKit supports all platforms supported by Swift 6 and later.

## Overview

JWTKit provides APIs for signing and verifying JSON Web Tokens, as specified by [RFC 7519](https://www.rfc-editor.org/rfc/rfc7519.html). The following features are supported:

- Signing and Verification with Custom Headers
- Customisable Parsing and Serialization
- JSON Web Keys (`JWK`, `JWKS`)

The following algorithms, as defined in [RFC 7518 § 3](https://www.rfc-editor.org/rfc/rfc7518.html#section-3) and [RFC 8037 § 3](https://www.rfc-editor.org/rfc/rfc8037.html#section-3), are supported for both signing and verification:

| JWS | Algorithm | Description |
| :-------------: | :-------------: | :----- |
| HS256 | HMAC256 | HMAC with SHA-256 |
| HS384 | HMAC384 | HMAC with SHA-384 |
| HS512 | HMAC512 | HMAC with SHA-512 |
| RS256 | RSA256 | RSASSA-PKCS1-v1_5 with SHA-256 |
| RS384 | RSA384 | RSASSA-PKCS1-v1_5 with SHA-384 |
| RS512 | RSA512 | RSASSA-PKCS1-v1_5 with SHA-512 |
| PS256 | RSA256PSS | RSASSA-PSS with SHA-256 |
| PS384 | RSA384PSS | RSASSA-PSS with SHA-384 |
| PS512 | RSA512PSS | RSASSA-PSS with SHA-512 |
| ES256 | ECDSA256 | ECDSA with curve P-256 and SHA-256 |
| ES384 | ECDSA384 | ECDSA with curve P-384 and SHA-384 |
| ES512 | ECDSA512 | ECDSA with curve P-521 and SHA-512 |
| EdDSA | EdDSA | EdDSA with Ed25519 |
| none | None | No digital signature or MAC |

## Vapor

The [vapor/jwt](https://github.com/vapor/jwt) package provides first-class integration with Vapor and is recommended for all Vapor projects which want to use JWTKit.

## Getting Started

A `JWTKeyCollection` object is used to load signing keys and keysets, and to sign and verify tokens:

@Snippet(path: "jwt-kit/Snippets/JWTKitExamples", slice: KEY_COLLECTION)

To add a signing key to the collection, use the `add` method for the respective algorithm:

@Snippet(path: "jwt-kit/Snippets/JWTKitExamples", slice: KEY_COLLECTION_ADD_HS256)

This example uses the _very_ secure key `"secret"`.

You can also add an optional key identifier (`kid`) to the key:

@Snippet(path: "jwt-kit/Snippets/JWTKitExamples", slice: KEY_COLLECTION_ADD_HS256_KID)

This is useful when you have multiple keys and need to select the correct one for verification. Based on the `kid` defined in the JWT header, the correct key will be selected for verification.
If you don't provide a `kid`, the key will be added to the collection as default.

To ensure thread-safety, `JWTKeyCollection` is an `actor`. This means that all of its methods are `async` and must be `await`ed.

### Signing

We can _generate_ JWTs, also known as signing. To demonstrate this, let's create a payload. Each property of the payload type corresponds to a claim in the token. JWTKit provides predefined types for all of the claims specified by RFC 7519, as well as some convenience types for working with custom claims. For the example token, the payload looks like this:

@Snippet(path: "jwt-kit/Snippets/JWTKitExamples", slice: EXAMPLE_PAYLOAD)

Then, pass the payload to `JWTKeyCollection.sign`.

@Snippet(path: "jwt-kit/Snippets/JWTKitExamples", slice: EXAMPLE_PAYLOAD_SIGN)

Here we've added a custom header to the JWT. Any key-value pair can be added to the header. In this case the `kid` will be used to look up the correct key for verification from the `JWTKeyCollection`.

You should see a JWT printed. This can be fed back into the `verify` method to access the payload.

### Verifying

Let's try to verify the following example JWT:

@Snippet(path: "jwt-kit/Snippets/JWTKitExamples", slice: VERIFYING)

You can inspect the contents of this token by visiting [jwt.io](https://jwt.io) and pasting the token in the debugger. Set the key in the "Verify Signature" section to `secret`.

To verify a token, the format of the payload must be known. In this case, we know that the payload is of type `ExamplePayload`. Using this payload, the `JWTKeyCollection` object can process and verify the example JWT, returning its payload on success:

@Snippet(path: "jwt-kit/Snippets/JWTKitExamples", slice: VERIFYING_PAYLOAD)

If all works correctly, this code will print something like this:

```swift
TestPayload(
    sub: SubjectClaim(value: "vapor"),
    exp: ExpirationClaim(value: 4001-01-01 00:00:00 +0000),
    admin: BoolClaim(value: true)
)
```

> Note:
> The `admin` property of the example payload did not have to use the `BoolClaim` type; a simple `Bool` would have worked as well. The `BoolClaim` type is provided by JWTKit for convenience in working with the many JWT implementations which encode boolean values as JSON strings (e.g. `"true"` and `"false"`) rather than using JSON's `true` and `false` keywords.

## JWK

A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data structure that represents a cryptographic key, defined in [RFC7517](https://www.rfc-editor.org/rfc/rfc7517.html). These are commonly used to supply clients with keys for verifying JWTs. For example, Apple hosts their _Sign in with Apple_ JWKS at the URL `https://appleid.apple.com/auth/keys`.

You can add this JSON Web Key Set (JWKS) to your `JWTSigners`:

@Snippet(path: "jwt-kit/Snippets/JWKExamples")

You can now pass JWTs from Apple to the `verify` method. The key identifier (`kid`) in the JWT header will be used to automatically select the correct key for verification. A JWKS may contain any of the key types supported by JWTKit.

## HMAC

HMAC is the simplest JWT signing algorithm. It uses a single key that can both sign and verify tokens. The key can be any length.

To add an HMAC key to the key collection, use the `addHS256`, `addHS384`, or `addHS512` methods:

@Snippet(path: "jwt-kit/Snippets/JWTKitExamples", slice: KEY_COLLECTION_ADD_HS256)

> Important:
> Cryptography is a complex topic, and the decision of algorithm can directly impact the integrity, security, and privacy of your data. This README does not attempt to offer a meaningful discussion of these concerns; the package authors recommend doing your own research before making a final decision.

## ECDSA

ECDSA is a modern asymmetric algorithm based on elliptic curve cryptography.
It uses a public key to verify tokens and a private key to sign them.

You can load ECDSA keys using PEM files:

@Snippet(path: "jwt-kit/Snippets/JWTKitExamples", slice: KEY_COLLECTION_CREATE_ES256)

Once you have an ECDSA key, you can add to the key collection using the following methods:

- `addES256`: ECDSA with SHA-256
- `addES384`: ECDSA with SHA-384
- `addES512`: ECDSA with SHA-512

@Snippet(path: "jwt-kit/Snippets/JWTKitExamples", slice: KEY_COLLECTION_ADD_ES256)

## EdDSA

EdDSA is a modern algorithm that is considered to be more secure than RSA and ECDSA. It is based on the Edwards-curve Digital Signature Algorithm. The only currently supported curve by JWTKit is Ed25519.

You can create an EdDSA key using its coordinates:

@Snippet(path: "jwt-kit/Snippets/JWTKitExamples", slice: EDDSA)

## RSA

RSA is an asymmetric algorithm. It uses a public key to verify tokens and a private key to sign them.

> Warning:
> RSA is no longer recommended for new applications. If possible, use EdDSA or ECDSA instead. [Infosec Insights' June 2020 blog post "ECDSA vs RSA: Everything You Need to Know"](https://sectigostore.com/blog/ecdsa-vs-rsa-everything-you-need-to-know/) provides a detailed discussion on the differences between the two.


To create an RSA signer, first initialize an `RSAKey`. This can be done by passing in the components:

@Snippet(path: "jwt-kit/Snippets/JWTKitExamples", slice: RSA)

The same initializer can be used for public keys without the `privateExponent` parameter.

You can also choose to load a PEM file:

@Snippet(path: "jwt-kit/Snippets/JWTKitExamples", slice: RSA_FROM_PEM)

Use `Insecure.RSA.PrivateKey(pem:)` for loading private RSA pem keys and `Insecure.RSA.PublicKey(certificatePEM:)` for loading X.509 certificates.
Once you have an RSA key, you can add to the key collection using the dedicated methods depending on the digest and the padding:

@Snippet(path: "jwt-kit/Snippets/JWTKitExamples", slice: RSA_ADD)

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

## Custom Parsing and Serialization

The `JWTParser` and `JWTSerializer` protocols allow you to define custom parsing and serialization for your payload types. This is useful when you need to work with a non-standard JWT format.

For example you might need to set the `b64` header to false, which does not base64 encode the payload. You can create your own `JWTParser` and `JWTSerializer` to handle this.

@Snippet(path: "jwt-kit/Snippets/JWTKitExamples", slice: CUSTOM_SERIALIZER)

And then use them like this:

@Snippet(path: "jwt-kit/Snippets/JWTKitExamples", slice: CUSTOM_SIGNING)

## Custom JSON Encoder and Decoder

If you don't need to specify custom parsing and serializing but you do need to use a custom JSON Encoder or Decoder, you can use the the `DefaultJWTParser` and `DefaultJWTSerializer` types to create a `JWTKeyCollection` with a custom JSON Encoder and Decoder.

@Snippet(path: "jwt-kit/Snippets/JWTKitExamples", slice: CUSTOM_ENCODING)

---

_This package was originally authored by the wonderful [@siemensikkema](https://github.com/siemensikkema)._
