/// A struct representing an Elliptic Curve used in EdDSA (Edwards-curve Digital Signature Algorithm).
///
/// ``EdDSACurve`` encapsulates different types of elliptic curves specifically used in EdDSA cryptographic operations.
/// It allows for representing and working with EdDSA curves.
/// The struct provides a static property for the Ed25519 curve, a widely used curve known for its
/// balance of security and efficiency. This makes ``EdDSACurve`` suitable for operations requiring Ed25519,
/// such as generating digital signatures or key pairs.
public struct EdDSACurve: Equatable, RawRepresentable, Sendable {
    let backing: Backing
    
    /// Textual representation of the curve.
    public var rawValue: String {
        backing.rawValue
    }
    
    /// Represents the Ed25519 curve.
    public static let ed25519 = Self(backing: .ed25519)
            
    enum Backing: String, Codable {
        case ed25519 = "Ed25519"
    }
    
    init(backing: Backing) {
        self.backing = backing
    }
    
    public init?(rawValue: String) {
        guard let backing = Backing(rawValue: rawValue) else {
            return nil
        }
        self.init(backing: backing)
    }
}
