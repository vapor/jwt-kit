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
public struct ECDSACurve: Sendable {
    let kind: Kind

    package static let p256 = Self(curve: .p256)
    package static let p384 = Self(curve: .p384)
    package static let p521 = Self(curve: .p521)
    package static let ed25519 = Self(curve: .ed25519)
    package static let ed448 = Self(curve: .ed448)
    
    enum Kind: String {
        case p256 = "P-256"
        case p384 = "P-384"
        case p521 = "P-521"
        case ed25519 = "Ed25519"
        case ed448 = "Ed448"
    }
    
    init(curve: Kind) {
        self.kind = curve
    }
    
    init(rawValue: String) throws {
        guard let kind = Kind(rawValue: rawValue) else {
            throw ECDSAError.wrongCurve
        }
        self.init(curve: kind)
    }
}

extension ECDSACurve: Equatable {}
