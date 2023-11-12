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
    package var curve: ECDSACurve = Curve.curve

    /// Parameters derived from the ECDSA key, if available.
    package var parameters: ECDSAParameters? {
        guard let privateKey else {
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
    var publicKey: PublicKey
    
    /// The current public key as a PEM encoded string.
    ///
    /// - Returns: A PEM encoded string representation of the key.
    public var publicKeyPEMRepresentation: String {
        publicKey.pemRepresentation
    }

    /// The current private key as a PEM encoded string.
    ///
    /// - Throws: If the key is not a private key.
    /// - Returns: A PEM encoded string representation of the key.
    public var privateKeyPEMRepresentation: String {
        get throws {
            guard let privateKey else {
                throw ECDSAError.noPrivateKey
            }
            return privateKey.pemRepresentation
        }
    }

    /// Generates a new ECDSA key.
    ///
    /// - Throws: If there is a problem generating the key.
    /// - Returns: A new ``ECDSAKey`` instance with a generated private and corresponding public key.
    public static func generate() throws -> Self {
        let privateKey = PrivateKey()
        return .init(privateKey: privateKey)
    }

    /// Creates an ``ECDSAKey`` instance from a PEM encoded certificate string.
    ///
    /// - Parameter pem: The PEM encoded certificate string.
    /// - Throws: If there is a problem parsing the certificate or deriving the public key.
    /// - Returns: A new ``ECDSAKey`` instance with the public key from the certificate.
    public static func certificate(pem string: String) throws -> Self {
        let cert = try X509.Certificate(pemEncoded: string)
        guard let publicKey = PublicKey(cert.publicKey) else {
            throw ECDSAError.generateKeyFailure
        }
        return .init(publicKey: publicKey)
    }

    /// Creates an ``ECDSAKey`` instance from a PEM encoded certificate data.
    ///
    /// - Parameter pem: The PEM encoded certificate data.
    /// - Throws: If there is a problem parsing the certificate or deriving the public key.
    /// - Returns: A new ``ECDSAKey`` instance with the public key from the certificate.
    public static func certificate(pem: some DataProtocol) throws -> Self {
        let string = String(decoding: pem, as: UTF8.self)
        return try certificate(pem: string)
    }

    /// Creates an ``ECDSAKey`` instance from a PEM encoded private key string.
    ///
    /// - Parameter pem: The PEM encoded private key string.
    /// - Throws: If there is a problem parsing the private key.
    /// - Returns: A new ``ECDSAKey`` instance with the private key.
    public static func `public`(pem string: String) throws -> Self {
        try .init(publicKey: PublicKey(pemRepresentation: string))
    }

    /// Creates an ``ECDSAKey`` instance from a PEM encoded private key data.
    ///
    /// - Parameter pem: The PEM encoded private key data.
    /// - Throws: If there is a problem parsing the private key.
    /// - Returns: A new ``ECDSAKey`` instance with the private key.
    public static func `public`(pem: some DataProtocol) throws -> Self {
        let string = String(decoding: pem, as: UTF8.self)
        return try self.public(pem: string)
    }

    /// Creates an ``ECDSAKey`` instance from a PEM encoded private key string.
    ///
    /// - Parameter pem: The PEM encoded private key string.
    /// - Throws: If there is a problem parsing the private key.
    /// - Returns: A new ``ECDSAKey`` instance with the private key.
    public static func `private`(pem string: String) throws -> Self {
        try .init(privateKey: PrivateKey(pemRepresentation: string))
    }

    /// Creates an ``ECDSAKey`` instance from a PEM encoded private key data.
    ///
    /// - Parameter data: The PEM encoded private key data.
    /// - Throws: If there is a problem parsing the private key.
    /// - Returns: A new ``ECDSAKey`` instance with the private key.
    public static func `private`(pem: some DataProtocol) throws -> Self {
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
    ///   - parameters: The ``ECDSAParameters`` tuple containing the x and y coordinates of the public key. These coordinates should be base64 URL encoded strings.
    ///   - privateKey: An optional base64 URL encoded string representation of the private key. If provided, it is used to create the private key for the instance. Defaults to `nil`.
    ///
    /// - Throws:
    ///   - ``JWTError/generic`` with the identifier `ecCoordinates` if the x and y coordinates from `parameters` cannot be interpreted as base64 encoded data.
    ///   - ``JWTError/generic`` with the identifier `ecPrivateKey` if the provided `privateKey` is non-nil but cannot be interpreted as a valid `PrivateKey`.
    ///
    /// - Note:
    ///   The ``ECDSAParameters`` tuple is assumed to have x and y properties that are base64 URL encoded strings representing the respective coordinates of an ECDSA public key.
    public init(parameters: ECDSAParameters, privateKey: String? = nil) throws {
        let privateKeyBytes: [UInt8]?
        if
            let privateKey,
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

        if let privateKeyBytes {
            guard let privateKey = try? PrivateKey(rawRepresentation: privateKeyBytes) else {
                throw JWTError.generic(identifier: "ecPrivateKey", reason: "Unable to interpret privateKey as ECDSAPrivateKey")
            }
            self.init(privateKey: privateKey)
        } else {
            self.init(publicKey: publicKey)
        }
    }
    
    init(privateKey: PrivateKey) {
        self.privateKey = privateKey
        self.publicKey = privateKey.publicKey
        self.type = .private
    }
    
    init(publicKey: PublicKey) {
        self.publicKey = publicKey
        self.type = .public
    }
}

extension ECDSAKey: Equatable {
    public static func == (lhs: ECDSAKey, rhs: ECDSAKey) -> Bool {
        lhs.parameters?.x == rhs.parameters?.x && lhs.parameters?.y == rhs.parameters?.y
    }
}
