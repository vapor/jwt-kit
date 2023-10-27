import Crypto
import Foundation
import SwiftASN1
import X509

/// A representation of an ECDSA key for a specific curve.
///
/// This struct encapsulates functionality and properties related to ECDSA keys.
/// It provides initializers and static methods to create keys from PEM representations,
/// certificates, and raw parameters. It also provides a way to generate new ECDSA keys.
///
/// - Generic Parameter Curve: The curve type associated with the ECDSA key.
public struct ECDSAKey<Curve>: ECDSAKeyType where Curve: ECDSACurveType {
    /// The elliptic curve used by this key.
    var curve: ECDSACurve = Curve.curve

    /// Parameters derived from the ECDSA key, if available.
    var parameters: ECDSAParameters? {
        guard let privateKey = privateKey else {
            return nil
        }
        let publicKey = privateKey.publicKey
        // 0x04 || x || y
        let x = publicKey.x963Representation[Curve.byteRanges.x].base64EncodedString()
        let y = publicKey.x963Representation[Curve.byteRanges.y].base64EncodedString()
        return (x, y)
    }

    typealias Signature = Curve.Signature
    typealias PrivateKey = Curve.PrivateKey
    typealias PublicKey = Curve.PrivateKey.PublicKey

    var type: KeyType

    var privateKey: PrivateKey?

    var publicKey: PublicKey?

    /// Generates a new ECDSA key.
    ///
    /// - Throws: If there is a problem generating the key.
    /// - Returns: A new `ECDSAKey` instance with a generated private and corresponding public key.
    public static func generate() throws -> Self {
        let privateKey = PrivateKey()
        return try .init(privateKey: privateKey, publicKey: privateKey.publicKey)
    }

    /// Creates an `ECDSAKey` instance from a PEM encoded certificate string.
    ///
    /// - Parameter pem: The PEM encoded certificate string.
    /// - Throws: If there is a problem parsing the certificate or deriving the public key.
    /// - Returns: A new `ECDSAKey` instance with the public key from the certificate.
    public static func certificate(pem string: String) throws -> Self {
        let cert = try X509.Certificate(pemEncoded: string)
        guard let publicKey = PublicKey(cert.publicKey) else {
            throw ECDSAError.generateKeyFailure
        }
        return try .init(publicKey: publicKey)
    }

    /// Creates an `ECDSAKey` instance from a PEM encoded certificate data.
    ///
    /// - Parameter pem: The PEM encoded certificate data.
    /// - Throws: If there is a problem parsing the certificate or deriving the public key.
    /// - Returns: A new `ECDSAKey` instance with the public key from the certificate.
    public static func certificate<Data>(pem: Data) throws -> Self
        where Data: DataProtocol
    {
        let string = String(decoding: pem, as: UTF8.self)
        return try certificate(pem: string)
    }

    /// Creates an `ECDSAKey` instance from a PEM encoded private key string.
    ///
    /// - Parameter pem: The PEM encoded private key string.
    /// - Throws: If there is a problem parsing the private key.
    /// - Returns: A new `ECDSAKey` instance with the private key.
    public static func `public`(pem string: String) throws -> Self {
        try .init(publicKey: PublicKey(pemRepresentation: string))
    }

    /// Creates an `ECDSAKey` instance from a PEM encoded private key data.
    ///
    /// - Parameter pem: The PEM encoded private key data.
    /// - Throws: If there is a problem parsing the private key.
    /// - Returns: A new `ECDSAKey` instance with the private key.
    public static func `public`<Data>(pem: Data) throws -> Self
        where Data: DataProtocol
    {
        let string = String(decoding: pem, as: UTF8.self)
        return try self.public(pem: string)
    }

    /// Creates an `ECDSAKey` instance from a PEM encoded private key string.
    ///
    /// - Parameter pem: The PEM encoded private key string.
    /// - Throws: If there is a problem parsing the private key.
    /// - Returns: A new `ECDSAKey` instance with the private key.
    public static func `private`(pem string: String) throws -> Self {
        try .init(privateKey: PrivateKey(pemRepresentation: string))
    }

    /// Creates an `ECDSAKey` instance from a PEM encoded private key data.
    ///
    /// - Parameter data: The PEM encoded private key data.
    /// - Throws: If there is a problem parsing the private key.
    /// - Returns: A new `ECDSAKey` instance with the private key.
    public static func `private`<Data>(pem: Data) throws -> Self
        where Data: DataProtocol
    {
        let string = String(decoding: pem, as: UTF8.self)
        return try self.private(pem: string)
    }

    /// Initializes a new instance with ECDSA parameters and an optional private key.
    ///
    /// This initializer takes ECDSA parameters and an optional private key in its base64 URL encoded string representation.
    /// If a private key is provided, it initializes the instance with the private key. If no private key is provided,
    /// it initializes the instance using only the public key derived from the given ECDSA parameters.
    ///
    /// - Parameters:
    ///   - parameters: The `ECDSAParameters` tuple containing the x and y coordinates of the public key. These coordinates should be base64 URL encoded strings.
    ///   - privateKey: An optional base64 URL encoded string representation of the private key. If provided, it is used to create the private key for the instance. Defaults to `nil`.
    ///
    /// - Throws:
    ///   - `JWTError.generic` with the identifier "ecCoordinates" if the x and y coordinates from `parameters` cannot be interpreted as base64 encoded data.
    ///   - `JWTError.generic` with the identifier "ecPrivateKey" if the provided `privateKey` is non-nil but cannot be interpreted as a valid ECDSAPrivateKey.
    ///
    /// - Note:
    ///   The ECDSAParameters tuple is assumed to have x and y properties that are base64 URL encoded strings representing the respective coordinates of an ECDSA public key.
    public init(parameters: ECDSAParameters, privateKey: String? = nil) throws {
        let privateKeyBytes: [UInt8]?
        if
            let privateKey = privateKey,
            let privateKeyData = privateKey.base64URLDecodedData()
        {
            privateKeyBytes = Array(privateKeyData)
        } else {
            privateKeyBytes = nil
        }

        guard
            let x = parameters.x.base64URLDecodedData(),
            let y = parameters.y.base64URLDecodedData()
        else {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "Unable to interpret x and y as base64 encoded data")
        }

        // The key is structured as: 0x04 || x || y
        let publicKey = try PublicKey(x963Representation: Data([0x04]) + x + y)

        if let privateKeyBytes = privateKeyBytes {
            guard let privateKey = try? PrivateKey(rawRepresentation: privateKeyBytes) else {
                throw JWTError.generic(identifier: "ecPrivateKey", reason: "Unable to interpret privateKey as ECDSAPrivateKey")
            }
            try self.init(privateKey: privateKey)
        } else {
            try self.init(publicKey: publicKey)
        }
    }

    init(privateKey: PrivateKey? = nil, publicKey: PublicKey? = nil) throws {
        guard privateKey != nil || publicKey != nil else {
            throw ECDSAError.generateKeyFailure
        }

        if privateKey != nil {
            type = .private
        } else if publicKey != nil {
            type = .public
        } else {
            type = .certificate
        }

        self.privateKey = privateKey
        self.publicKey = publicKey
    }
}
