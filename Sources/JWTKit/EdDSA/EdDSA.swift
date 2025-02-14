import Crypto

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

/// Namespace for the EdDSA (Edwards-curve Digital Signature Algorithm) signing algorithm.
/// EdDSA is a modern signing algorithm that is efficient and fast.
public enum EdDSA: Sendable {}

/// This protocol represents a key that can be used for signing and verifying EdDSA signatures.
/// Both ``EdDSA.PublicKey`` and ``EdDSA.PrivateKey`` conform to this protocol.
public protocol EdDSAKey: Sendable {}

extension EdDSA {
    /// A struct representing a public key used in EdDSA (Edwards-curve Digital Signature Algorithm).
    ///
    /// In JWT, EdDSA public keys are represented as a single x-coordinate and are used for verifying signatures.
    /// Currently, only the ``EdDSACurve/ed25519`` curve is supported.
    public struct PublicKey: EdDSAKey {
        let backing: Curve25519.Signing.PublicKey
        let curve: EdDSACurve

        /// Creates an ``EdDSA.PublicKey`` instance using the provided public key.
        ///
        /// This init constructs an ``EdDSA.PublicKey`` based on the corresponding SwiftCrypto
        /// ``Curve25519.Signing.PublicKey``.
        /// - Parameter backing: The SwiftCrypto ``Curve25519.Signing.PublicKey``
        public init(backing: Curve25519.Signing.PublicKey) {
            self.backing = backing
            self.curve = .ed25519
        }

        /// Creates an ``EdDSA.PublicKey`` instance using the public key x-coordinate and specified curve.
        ///
        /// This init allows for the creation of an ``EdDSA.PublicKey`` using the x-coordinate of the public key.
        /// The provided x-coordinate should be a Base64 URL encoded string.
        ///
        /// - Parameters:
        ///   - x: A `String` representing the x-coordinate of the public key. This should be a Base64 URL encoded string.
        ///   - curve: The ``EdDSACurve`` representing the elliptic curve used for the EdDSA public key.
        ///
        /// - Throws:
        ///   - ``EdDSAError/publicKeyMissing`` if the x-coordinate data is missing or cannot be properly converted.
        public init(x: String, curve: EdDSACurve) throws {
            guard
                let xData = x.base64URLDecodedData(),
                !xData.isEmpty
            else {
                throw EdDSAError.publicKeyMissing
            }

            let key =
                switch curve.backing {
                case .ed25519:
                    try Curve25519.Signing.PublicKey(rawRepresentation: xData)
                }

            self.init(backing: key)
        }

        var rawRepresentation: Data {
            self.backing.rawRepresentation
        }
    }
}

extension EdDSA {
    /// A struct representing a private key used in EdDSA (Edwards-curve Digital Signature Algorithm).
    ///
    /// In JWT, EdDSA private keys are represented as a pair of x-coordinate and private key (d) and are used for signing.
    /// Currently, only the ``Curve/ed25519`` curve is supported.
    public struct PrivateKey: EdDSAKey {
        let backing: Curve25519.Signing.PrivateKey
        let curve: EdDSACurve

        /// Generates a new ``EdDSAKey`` instance with both public and private key components.
        ///
        /// This method generates a new key pair suitable for signing and verifying signatures.
        /// The generated keys use the specified curve, currently limited to ``Curve/ed25519``.
        ///
        /// - Parameter curve: The curve to be used for key generation.
        /// - Throws: An error if key generation fails.
        /// - Returns: A new ``EdDSA.PrivateKey`` instance with a freshly generated key pair.
        public init(curve: EdDSACurve = .ed25519) throws {
            let key =
                switch curve.backing {
                case .ed25519:
                    Curve25519.Signing.PrivateKey()
                }

            self.init(backing: key)
        }

        /// Creates an ``EdDSA.PrivateKey`` instance using the provided private key.
        ///
        /// This init constructs an ``EdDSA.PrivateKey`` based on the corresponding SwiftCrypto
        /// ``Curve25519.Signing.PrivateKey``.
        /// - Parameter privateKey: The SwiftCrypto ``Curve25519.Signing.PrivateKey``
        public init(backing: Curve25519.Signing.PrivateKey) {
            self.backing = backing
            self.curve = .ed25519
        }

        /// Creates an ``EdDSA.PrivateKey`` instance using both the public and private key components along with the specified curve.
        ///
        /// This init constructs an ``EdDSA.PrivateKey`` from the provided private key (d).
        /// `d` is expected to be a Base64 URL encoded string.
        ///
        /// - Parameters:
        ///   - d: A `String` representing the private key, encoded in Base64 URL format.
        ///   - curve: The ``EdDSACurve`` representing the elliptic curve used for the EdDSA key.
        ///
        /// - Throws:
        ///   - ``EdDSAError/privateKeyMissing`` if the private key data is missing or cannot be properly converted.
        public init(d: String, curve: EdDSACurve) throws {
            guard
                let dData = d.base64URLDecodedData(),
                !dData.isEmpty
            else {
                throw EdDSAError.privateKeyMissing
            }

            let key =
                switch curve.backing {
                case .ed25519:
                    try Curve25519.Signing.PrivateKey(rawRepresentation: dData)
                }

            self.init(backing: key)
        }

        var publicKey: PublicKey {
            .init(backing: self.backing.publicKey)
        }

        var rawRepresentation: Data {
            self.backing.rawRepresentation
        }
    }
}

// TODO: Remove @unchecked Sendable when Crypto is updated to use Sendable
extension Curve25519.Signing.PublicKey: @unchecked @retroactive Sendable {}
extension Curve25519.Signing.PrivateKey: @unchecked @retroactive Sendable {}
