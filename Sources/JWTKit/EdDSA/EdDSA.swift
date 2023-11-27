import Crypto
import Foundation

/// Namespace for the EdDSA (Edwards-curve Digital Signature Algorithm) signing algorithm.
/// EdDSA is a modern signing algorithm that is efficient and fast.
public enum EdDSA: Sendable {}

/// This protocol represents a key that can be used for signing and verifying EdDSA signatures.
/// Both ``EdDSA.PublicKey`` and ``EdDSA.PrivateKey`` conform to this protocol.
public protocol EdDSAKey: Sendable {}

public extension EdDSA {
    /// A struct representing a public key used in EdDSA (Edwards-curve Digital Signature Algorithm).
    ///
    /// In JWT, EdDSA public keys are represented as a single x-coordinate and are used for verifying signatures.
    /// Currently, only the ``Curve/ed25519`` curve is supported.
    struct PublicKey: EdDSAKey {
        // https://www.rfc-editor.org/rfc/rfc8037.html#appendix-A.2
        struct OctetKeyPair: Sendable {
            let x: Data

            init(x: Data) {
                self.x = x
            }
        }

        let keyPair: OctetKeyPair

        let curve: EdDSACurve

        var rawRepresentation: Data {
            keyPair.x
        }

        /// Creates an ``EdDSA.PublicKey`` instance using the public key x-coordinate and specified curve.
        ///
        /// This init allows for the creation of an ``EdDSA.PublicKey`` using the x-coordinate of the public key.
        /// The provided x-coordinate should be a Base64 URL encoded string.
        ///
        /// - Parameters:
        ///   - x: A `String` representing the x-coordinate of the public key. This should be a Base64 URL encoded string.
        ///   - curve: The ``Curve`` representing the elliptic curve used for the EdDSA public key.
        ///
        /// - Throws:
        ///   - ``EdDSAError/publicKeyMissing`` if the x-coordinate data is missing or cannot be properly converted.
        public init(x: String, curve: EdDSACurve) throws {
            guard let xData = x.data(using: .utf8), !xData.isEmpty else {
                throw EdDSAError.publicKeyMissing
            }

            self.init(keyPair: .init(
                x: Data(xData.base64URLDecodedBytes())
            ), curve: curve)
        }

        fileprivate init(keyPair: OctetKeyPair, curve: EdDSACurve) {
            self.keyPair = keyPair
            self.curve = curve
        }
    }
}

public extension EdDSA {
    /// A struct representing a private key used in EdDSA (Edwards-curve Digital Signature Algorithm).
    ///
    /// In JWT, EdDSA private keys are represented as a pair of x-coordinate and private key (d) and are used for signing.
    /// Currently, only the ``Curve/ed25519`` curve is supported.
    struct PrivateKey: EdDSAKey {
        // https://www.rfc-editor.org/rfc/rfc8037.html#appendix-A.1
        struct OctetKeyPair: Sendable {
            let x: Data
            let d: Data

            init(x: Data, d: Data) {
                self.x = x
                self.d = d
            }
        }

        let keyPair: OctetKeyPair

        let curve: EdDSACurve

        var publicKey: PublicKey {
            .init(keyPair: .init(x: keyPair.x), curve: curve)
        }

        var rawRepresentation: Data {
            keyPair.d
        }

        /// Generates a new ``EdDSAKey`` instance with both public and private key components.
        ///
        /// This method generates a new key pair suitable for signing and verifying signatures.
        /// The generated keys use the specified curve, currently limited to ``Curve/ed25519``.
        ///
        /// - Parameter curve: The curve to be used for key generation.
        /// - Throws: An error if key generation fails.
        /// - Returns: A new ``EdDSAKey`` instance with a freshly generated key pair.
        public init(curve: EdDSACurve = .ed25519) throws {
            switch curve.backing {
            case .ed25519:
                let keyPair = Curve25519.Signing.PrivateKey()
                self.init(keyPair: .init(
                    x: keyPair.publicKey.rawRepresentation,
                    d: keyPair.rawRepresentation
                ), curve: curve)
            }
        }

        /// Creates an ``EdDSA.PrivateKey`` instance using both the public and private key components along with the specified curve.
        ///
        /// This init constructs an ``EdDSA.PrivateKey`` from the provided x-coordinate of the public key and the private key (d).
        /// Both `x` and `d` are expected to be Base64 URL encoded strings.
        ///
        /// - Parameters:
        ///   - x: A `String` representing the x-coordinate of the public key, encoded in Base64 URL format.
        ///   - d: A `String` representing the private key, encoded in Base64 URL format.
        ///   - curve: The ``Curve`` representing the elliptic curve used for the EdDSA key.
        ///
        /// - Throws:
        ///   - ``EdDSAError/publicKeyMissing`` if the x-coordinate data is missing or cannot be properly converted.
        ///   - ``EdDSAError/privateKeyMissing`` if the private key data is missing or cannot be properly converted.
        public init(x: String, d: String, curve: EdDSACurve) throws {
            guard let xData = x.data(using: .utf8), !xData.isEmpty else {
                throw EdDSAError.publicKeyMissing
            }

            guard let dData = d.data(using: .utf8), !dData.isEmpty else {
                throw EdDSAError.privateKeyMissing
            }

            self.init(keyPair: .init(
                x: Data(xData.base64URLDecodedBytes()),
                d: Data(dData.base64URLDecodedBytes())
            ), curve: curve)
        }

        private init(keyPair: OctetKeyPair, curve: EdDSACurve) {
            self.keyPair = keyPair
            self.curve = curve
        }
    }
}
