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
public struct ECDSACurve: LosslessStringConvertible, Sendable {
    let backing: Backing
    
    public var description: String {
        backing.rawValue
    }

    package static let p256 = Self(backing: .p256)
    package static let p384 = Self(backing: .p384)
    package static let p521 = Self(backing: .p521)
    package static let ed25519 = Self(backing: .ed25519)
    package static let ed448 = Self(backing: .ed448)
    
    enum Backing: String {
        case p256 = "P-256"
        case p384 = "P-384"
        case p521 = "P-521"
        case ed25519 = "Ed25519"
        case ed448 = "Ed448"
    }
    
    init(backing: Backing) {
        self.backing = backing
    }
    
    public init?(_ description: String) {
        guard let backing = Backing(rawValue: description) else {
            return nil
        }
        self.init(backing: backing)
    }
}

extension ECDSACurve: Equatable {}
