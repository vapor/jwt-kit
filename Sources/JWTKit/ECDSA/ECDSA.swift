import Crypto
import Foundation
import SwiftASN1
import X509

public enum ECDSA: Sendable {}

public protocol ECDSAKey: Sendable {
    associatedtype Curve: ECDSACurveType
}

public extension ECDSA {
    struct PublicKey<Curve>: ECDSAKey where Curve: ECDSACurveType {
        typealias Signature = Curve.Signature
        typealias PublicKey = Curve.PrivateKey.PublicKey

        package var curve: ECDSACurve = Curve.curve

        package var parameters: ECDSAParameters? {
            // 0x04 || x || y
            let x = backing.x963Representation[Curve.byteRanges.x].base64EncodedString()
            let y = backing.x963Representation[Curve.byteRanges.y].base64EncodedString()
            return (x, y)
        }

        var backing: PublicKey

        /// The current public key as a PEM encoded string.
        ///
        /// - Returns: A PEM encoded string representation of the key.
        public var pemRepresentation: String {
            backing.pemRepresentation
        }

        /// Creates an ``ECDSA.PublicKey`` instance from a PEM encoded certificate string.
        ///
        /// - Parameter pem: The PEM encoded certificate string.
        /// - Throws: If there is a problem parsing the certificate or deriving the public key.
        /// - Returns: A new ``ECDSAKey`` instance with the public key from the certificate.
        public init(certificate pem: String) throws {
            let certificate = try X509.Certificate(pemEncoded: pem)
            guard let publicKey = PublicKey(certificate.publicKey) else {
                throw ECDSAError.generateKeyFailure
            }
            backing = publicKey
        }

        /// Creates an ``ECDSA.PublicKey`` instance from a PEM encoded certificate data.
        ///
        /// - Parameter pem: The PEM encoded certificate data.
        /// - Throws: If there is a problem parsing the certificate or deriving the public key.
        /// - Returns: A new ``ECDSA.PublicKey`` instance with the public key from the certificate.
        public init(certificate pem: some DataProtocol) throws {
            try self.init(certificate: String(decoding: pem, as: UTF8.self))
        }

        /// Creates an ``ECDSA.PublicKey`` instance from a PEM encoded public key string.
        ///
        /// - Parameter pem: The PEM encoded public key string.
        /// - Throws: If there is a problem parsing the public key.
        /// - Returns: A new ``ECDSA.PublicKey`` instance with the public key from the certificate.
        public init(pem string: String) throws {
            backing = try PublicKey(pemRepresentation: string)
        }

        /// Creates an ``ECDSA.PublicKey`` instance from a PEM encoded public key data.
        ///
        /// - Parameter pem: The PEM encoded public key data.
        /// - Throws: If there is a problem parsing the public key.
        /// - Returns: A new ``ECDSA.PublicKey`` instance with the public key from the certificate.
        public init(pem data: some DataProtocol) throws {
            try self.init(pem: String(decoding: data, as: UTF8.self))
        }

        /// Initializes a new ``ECDSA.PublicKey` with ECDSA parameters.
        ///
        /// - Parameters:
        ///   - parameters: The ``ECDSAParameters`` tuple containing the x and y coordinates of the public key. These coordinates should be base64 URL encoded strings.
        ///
        /// - Throws:
        ///   - ``JWTError/generic`` with the identifier `ecCoordinates` if the x and y coordinates from `parameters` cannot be interpreted as base64 encoded data.
        ///   - ``JWTError/generic`` with the identifier `ecPrivateKey` if the provided `privateKey` is non-nil but cannot be interpreted as a valid `PrivateKey`.
        ///
        /// - Note:
        ///   The ``ECDSAParameters`` tuple is assumed to have x and y properties that are base64 URL encoded strings representing the respective coordinates of an ECDSA public key.
        public init(parameters: ECDSAParameters) throws {
            guard
                let x = parameters.x.base64URLDecodedData(),
                let y = parameters.y.base64URLDecodedData()
            else {
                throw JWTError.generic(identifier: "ecCoordinates", reason: "Unable to interpret x or y as base64 encoded data")
            }
            backing = try PublicKey(x963Representation: [0x04] + x + y)
        }

        init(backing: PublicKey) {
            self.backing = backing
        }
    }
}

public extension ECDSA {
    struct PrivateKey<Curve>: ECDSAKey where Curve: ECDSACurveType {
        typealias PrivateKey = Curve.PrivateKey
        typealias Signature = PrivateKey.Signature

        package var curve: ECDSACurve = Curve.curve

        package var parameters: ECDSAParameters? {
            publicKey.parameters
        }

        var backing: PrivateKey

        public var publicKey: PublicKey<Curve> {
            .init(backing: backing.publicKey)
        }

        /// The current private key as a PEM encoded string.
        ///
        /// - Returns: A PEM encoded string representation of the key.
        public var pemRepresentation: String {
            backing.pemRepresentation
        }

        /// Creates an ``ECDSA.PrivateKey`` instance from a PEM encoded private key string.
        ///
        /// - Parameter pem: The PEM encoded private key string.
        /// - Throws: If there is a problem parsing the private key.
        /// - Returns: A new ``ECDSA.PrivateKey`` instance with the private key.
        public init(pem string: String) throws {
            backing = try PrivateKey(pemRepresentation: string)
        }

        /// Creates an ``ECDSA.PrivateKey`` instance from a PEM encoded private key data.
        ///
        /// - Parameter pem: The PEM encoded private key data.
        /// - Throws: If there is a problem parsing the private key.
        /// - Returns: A new ``ECDSA.PrivateKey`` instance with the private key.
        public init(pem data: some DataProtocol) throws {
            try self.init(pem: String(decoding: data, as: UTF8.self))
        }

        /// Initializes a new ``ECDSA.PrivateKey`` with ECDSA parameters.
        ///
        /// - Parameters:
        ///   - parameters: The ``ECDSAParameters`` tuple containing the x and y coordinates of the public key. These coordinates should be base64 URL encoded strings.
        ///   - privateKey: A base64 URL encoded string representation of the private key. If provided, it is used to create the private key for the instance. Defaults to `nil`.
        ///
        /// - Throws:
        ///   - ``JWTError/generic`` with the identifier `ecCoordinates` if the x and y coordinates from `parameters` cannot be interpreted as base64 encoded data.
        ///   - ``JWTError/generic`` with the identifier `ecPrivateKey` if the provided `privateKey` is non-nil but cannot be interpreted as a valid `PrivateKey`.
        ///
        /// - Note:
        ///   The ``ECDSAParameters`` tuple is assumed to have x and y properties that are base64 URL encoded strings representing the respective coordinates of an ECDSA public key.
        public init(key: String) throws {
            guard let keyData = key.base64URLDecodedData() else {
                throw JWTError.generic(identifier: "ECDSAKey Creation", reason: "Unable to interpret private key data as base64URL")
            }

            backing = try PrivateKey(rawRepresentation: [UInt8](keyData))
        }

        /// Generates a new ECDSA key.
        ///
        /// - Returns: A new ``ECDSA.PrivateKey`` instance with the generated key.
        public init() {
            backing = PrivateKey()
        }
    }
}
