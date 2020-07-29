# Contributing to JWTKit

See [Vapor's contributing.md](https://github.com/vapor/vapor/blob/master/.github/contributing.md) for general information on contributing to Vapor packages.

### Dependencies

JWTKit doesn't require any external dependencies to build and test. 

### BoringSSL

This package ships a private copy of BoringSSL which powers the RSA, ECDSA, and HMAC signers. This design is inspired by [swift-crypto](https://github.com/apple/swift-crypto) and [swift-nio-ssl](https://github.com/apple/swift-nio-ssl). 

To update the vendored BoringSSL version to the latest version, use the [scripts/vendor-boringssl.sh](scripts/vendor-boringssl.sh) script.

### Maintainers

- [@tanner0101](https://github.com/tanner0101/)
- [@grosch](https://github.com/grosch)
