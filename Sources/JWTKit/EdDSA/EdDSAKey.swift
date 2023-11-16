import Crypto
import Foundation

/// A structure representing an EdDSA (Edwards-curve Digital Signature Algorithm) key.
///
/// ``EdDSAKey`` is used to represent keys for EdDSA, a digital signature scheme using
/// a variant of the Schnorr signature based on twisted Edwards curves. This structure
/// provides functionalities to create and manage EdDSA keys.
///
/// It supports the `Ed25519` curve, widely recognized for its strength and efficiency.
public struct EdDSAKey: Sendable {
    /// An enum defining supported curves for EdDSA keys.
    public struct Curve: Codable, Equatable, RawRepresentable, Sendable {
        public typealias RawValue = String
        
        let backing: Backing
        
        public var rawValue: String {
            backing.rawValue
        }
        
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

    let keyPair: OctetKeyPair
    var publicKey: Data {
        keyPair.publicKey
    }

    var privateKey: Data? {
        keyPair.privateKey
    }

    let curve: Curve

    /// Creates an ``EdDSAKey`` instance using the public key x-coordinate and specified curve.
    ///
    /// This function allows for the creation of an ``EdDSAKey`` using the x-coordinate of the public key.
    /// The provided x-coordinate should be a Base64 URL encoded string. This method is particularly useful
    /// when you have the x-coordinate of a public key and the curve information, and you need to construct
    /// an ``EdDSAKey`` instance for cryptographic operations.
    ///
    /// - Parameters:
    ///   - x: A `String` representing the x-coordinate of the public key. This should be a Base64 URL encoded string.
    ///   - curve: The ``Curve`` representing the elliptic curve used for the EdDSA public key.
    ///
    /// - Throws:
    ///   - ``EdDSAError/publicKeyMissing`` if the x-coordinate data is missing or cannot be properly converted.
    ///
    /// - Returns: An initialized ``EdDSAKey`` instance with the provided public key data and curve.
    public static func `public`(x: String, curve: Curve) throws -> EdDSAKey {
        guard let xData = x.data(using: .utf8), !xData.isEmpty else {
            throw EdDSAError.publicKeyMissing
        }

        return try EdDSAKey(
            keyPair: .public(
                x: Data(xData.base64URLDecodedBytes())
            ),
            curve: curve
        )
    }

    /// Creates an ``EdDSAKey`` instance using both the public and private key components along with the specified curve.
    ///
    /// This function facilitates the construction of an ``EdDSAKey`` from the provided x-coordinate of the public key and the private key (d).
    /// Both `x` and `d` are expected to be Base64 URL encoded strings. This method is particularly useful when reconstructing an ``EdDSAKey``
    /// from known components, especially in scenarios involving key serialization/deserialization.
    ///
    /// - Parameters:
    ///   - x: A `String` representing the x-coordinate of the public key, encoded in Base64 URL format.
    ///   - d: A `String` representing the private key, encoded in Base64 URL format.
    ///   - curve: The ``Curve`` representing the elliptic curve used for the EdDSA key.
    ///
    /// - Throws:
    ///   - ``EdDSAError/publicKeyMissing`` if the x-coordinate data is missing or cannot be properly converted.
    ///   - ``EdDSAError/privateKeyMissing`` if the private key data is missing or cannot be properly converted.
    ///
    /// - Returns: An initialized ``EdDSAKey`` instance with the specified public and private key components and curve.
    public static func `private`(x: String, d: String, curve: Curve) throws -> EdDSAKey {
        guard let xData = x.data(using: .utf8), !xData.isEmpty else {
            throw EdDSAError.publicKeyMissing
        }

        guard let dData = d.data(using: .utf8), !dData.isEmpty else {
            throw EdDSAError.privateKeyMissing
        }

        return try EdDSAKey(
            keyPair: .private(
                x: Data(xData.base64URLDecodedBytes()),
                d: Data(dData.base64URLDecodedBytes())
            ),
            curve: curve
        )
    }

    init(keyPair: OctetKeyPair, curve: Curve) throws {
        self.keyPair = keyPair
        self.curve = curve
    }

    /// Generates a new ``EdDSAKey`` instance with both public and private key components.
    ///
    /// This method generates a new key pair suitable for signing and verifying signatures.
    /// The generated keys use the specified curve, currently limited to ``Curve/ed25519``.
    ///
    /// - Parameter curve: The curve to be used for key generation.
    /// - Throws: An error if key generation fails.
    /// - Returns: A new ``EdDSAKey`` instance with a freshly generated key pair.
    public static func generate(curve: Curve) throws -> EdDSAKey {
        switch curve.backing {
        case .ed25519:
            let key = Curve25519.Signing.PrivateKey()
            return try .init(
                keyPair: .private(
                    x: key.publicKey.rawRepresentation,
                    d: key.rawRepresentation
                ),
                curve: curve
            )
        }
    }
}
