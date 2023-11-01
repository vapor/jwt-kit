import Crypto
import Foundation

public struct EdDSAKey: Sendable {
    public enum Curve: String, Codable, Sendable {
        case ed25519 = "Ed25519"
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

    public static func generate(curve: Curve) throws -> EdDSAKey {
        switch curve {
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
