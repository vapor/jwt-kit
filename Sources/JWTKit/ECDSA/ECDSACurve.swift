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
public struct ECDSACurve: Codable, RawRepresentable, Sendable {
    let backing: Backing

    /// Textual representation of the elliptic curve.
    public var rawValue: String {
        backing.rawValue
    }

    /// Represents the P-256 elliptic curve.
    public static let p256 = Self(.p256)

    /// Represents the P-384 elliptic curve.
    public static let p384 = Self(.p384)

    /// Represents the P-521 elliptic curve.
    public static let p521 = Self(.p521)

    enum Backing: String, Codable {
        case p256 = "P-256"
        case p384 = "P-384"
        case p521 = "P-521"
    }

    init(_ backing: Backing) {
        self.backing = backing
    }

    public init?(rawValue: String) {
        guard let backing = Backing(rawValue: rawValue) else {
            return nil
        }
        self.init(backing)
    }

    public init(from decoder: any Decoder) throws {
        try self.init(decoder.singleValueContainer().decode(Backing.self))
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.backing)
    }
}

extension ECDSACurve: Equatable {}
