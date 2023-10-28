/// A struct representing an Elliptic Curve used in Elliptic Curve Digital Signature Algorithm (ECDSA).
///
/// ``ECDSACurve`` encapsulates the different types of elliptic curves used in cryptographic operations,
/// particularly in signing and verifying digital signatures with ECDSA. Each instance of ``ECDSACurve``
/// represents a specific elliptic curve, identified by its standardized curve name.
///
/// The struct provides predefined static properties for common elliptic curves, such as P-256, P-384, P-521,
/// and others. These are widely used curves, each offering different levels of security and performance characteristics.
///
/// The use of ``ECDSACurve`` in cryptographic operations allows for easy specification and interchange of
/// the elliptic curves based on security requirements and application needs.
public struct ECDSACurve {
    let curve: String

    static var p256: Self {
        Self(curve: "P-256")
    }

    static var p384: Self {
        Self(curve: "P-384")
    }

    static var p521: Self {
        Self(curve: "P-521")
    }

    static var ed25519: Self {
        Self(curve: "Ed25519")
    }

    static var ed448: Self {
        Self(curve: "Ed448")
    }
}

extension ECDSACurve: Equatable {}
