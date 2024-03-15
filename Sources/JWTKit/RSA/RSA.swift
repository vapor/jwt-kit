import _CryptoExtras
import Crypto
import Foundation
import SwiftASN1
import X509

public extension Insecure {
    /// Namespace encompassing functionality related to the RSA (Rivest–Shamir–Adleman) cryptographic algorithm.
    /// Relatively to other algorithms such as ECDSA and EdDSA, RSA is considered slow and should be avoided when possible.
    enum RSA: Sendable {}
}

/// The `RSAKey` protocol defines the common interface for both public and private RSA keys.
/// Implementers of this protocol can represent keys used for cryptographic operations in the RSA algorithm.
public protocol RSAKey: Sendable {}

public extension Insecure.RSA {
    /// A structure representing a public RSA key.
    ///
    /// In JWT, RSA public keys are used to verify JWTs.
    /// They consist of a modulus and an exponent.
    struct PublicKey: RSAKey {
        // Exports the current public key as a PEM encoded string.
        ///
        /// - Returns: A PEM encoded string representation of the key.
        public var pemRepresentation: String {
            backing.pemRepresentation
        }

        /// Exports the current public key as a DER encoded data.
        ///
        /// - Returns: A DER encoded data representation of the key.
        public var derRepresentation: Data {
            backing.derRepresentation
        }

        private let backing: _RSA.Signing.PublicKey

        /// Creates an ``RSA.PublicKey`` from a SwiftCrypto public key.
        ///
        /// - Parameter backing: The SwiftCrypto public key.
        /// - Throws: ``RSAError/keySizeTooSmall`` if the key size is less than 2048 bits.
        public init(backing: _RSA.Signing.PublicKey) throws {
            guard backing.keySizeInBits >= 2048 else {
                throw RSAError.keySizeTooSmall
            }
            self.backing = backing
        }

        /// Creates an ``RSA.PublicKey`` from public key PEM file.
        ///
        /// Public key PEM files look like:
        ///
        ///     -----BEGIN PUBLIC KEY-----
        ///     MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
        ///     ...
        ///     aX4rbSL49Z3dAQn8vQIDAQAB
        ///     -----END PUBLIC KEY-----
        ///
        /// This key can only be used to verify JWTs.
        ///
        /// - Parameters:
        ///   - pem: Contents of PEM file.
        /// - Throws: ``RSAError/keySizeTooSmall`` if the key size is less than 2048 bits.
        public init(pem: String) throws {
            try self.init(backing: .init(pemRepresentation: pem))
        }

        /// Creates an ``RSA.PublicKey`` from public key PEM file.
        ///
        /// Public key PEM files look like:
        ///
        ///     -----BEGIN PUBLIC KEY-----
        ///     MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
        ///     ...
        ///     aX4rbSL49Z3dAQn8vQIDAQAB
        ///     -----END PUBLIC KEY-----
        ///
        /// This key can only be used to verify JWTs.
        ///
        /// - Parameters:
        ///   - pem: Contents of PEM file.
        /// - Throws: ``RSAError/keySizeTooSmall`` if the key size is less than 2048 bits.
        public init(pem data: some DataProtocol) throws {
            let string = String(decoding: data, as: UTF8.self)
            try self.init(pem: string)
        }

        /// Creates an ``RSA.PublicKey`` from public certificate PEM file.
        ///
        /// Certificate pem files look like:
        ///
        ///     -----BEGIN CERTIFICATE-----
        ///     MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
        ///     ...
        ///     aX4rbSL49Z3dAQn8vQIDAQAB
        ///     -----END CERTIFICATE-----
        ///
        /// This key can only be used to verify JWTs.
        ///
        /// - Parameters:
        ///   - pem: Contents of pem file.
        /// - Throws: ``RSAError/keyInitializationFailure`` if the key cannot be initialized.
        public init(certificatePEM: String) throws {
            let cert = try X509.Certificate(pemEncoded: certificatePEM)
            guard let publicKey = _RSA.Signing.PublicKey(cert.publicKey) else {
                throw RSAError.keyInitializationFailure
            }
            try self.init(pem: publicKey.pemRepresentation)
        }

        /// Creates an ``RSA.PublicKey`` from public certificate PEM file.
        ///
        /// Certificate PEM files look like:
        ///
        ///     -----BEGIN CERTIFICATE-----
        ///     MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
        ///     ...
        ///     aX4rbSL49Z3dAQn8vQIDAQAB
        ///     -----END CERTIFICATE-----
        ///
        /// This key can only be used to verify JWTs.
        ///
        /// - Parameters:
        ///   - pem: Contents of PEM file.
        /// - Throws: ``RSAError/keyInitializationFailure`` if the key cannot be initialized.
        public init(certificatePEM: some DataProtocol) throws {
            let string = String(decoding: certificatePEM, as: UTF8.self)
            try self.init(certificatePEM: string)
        }

        /// Initializes a new RSA key instance with modulus and exponent
        ///
        /// This initializer creates an RSA key using the modulus and exponent.
        /// All these parameters are expected to be base64 URL encoded strings.
        ///
        /// - Parameters:
        ///   - modulus: The modulus of the RSA key, represented as a base64 URL encoded string.
        ///   - exponent: The exponent of the RSA key, represented as a base64 URL encoded string.
        ///
        /// - Throws:
        ///   - ``JWTError/generic`` with the identifier `RSAKey`` if either the modulus or exponent cannot be decoded from their base64 URL encoded strings.
        ///
        /// - Note:
        ///   - The provided modulus and exponent are key components for creating RSA public keys.
        ///   - The private exponent is an additional parameter required for creating RSA private keys.
        public init(
            modulus: String,
            exponent: String
        ) throws {
            guard let n = modulus.base64URLDecodedData() else {
                throw JWTError.generic(identifier: "RSAKey", reason: "Unable to decode base64url modulus")
            }

            guard let e = exponent.base64URLDecodedData() else {
                throw JWTError.generic(identifier: "RSAKey", reason: "Unable to decode base64url exponent")
            }

            var serializer = DER.Serializer()

            let publicKeyDER = try Insecure.RSA.calculateDER(n: n, e: e)
            try publicKeyDER.serialize(into: &serializer)
            let publicKey = try _RSA.Signing.PublicKey(derRepresentation: serializer.serializedBytes)
            try self.init(backing: publicKey)
        }

        func isValidSignature<D: Digest>(_ signature: _RSA.Signing.RSASignature, for digest: D, padding: _RSA.Signing.Padding) -> Bool {
            self.backing.isValidSignature(signature, for: digest, padding: padding)
        }
    }
}

public extension Insecure.RSA {
    /// A structure representing a private RSA key.
    ///
    /// In JWT, RSA private keys are used to sign JWTs.
    /// They consist of a modulus, an exponent, and a private exponent.
    struct PrivateKey: RSAKey {
        /// Exports the current private key as a PEM encoded string.
        ///
        /// - Throws: If the key is not a private key.
        /// - Returns: A PEM encoded string representation of the key.
        public var pemRepresentation: String {
            backing.pemRepresentation
        }

        /// Exports the current private key as a DER encoded data.
        ///
        /// - Returns: A DER encoded data representation of the key.
        public var derRepresentation: Data {
            backing.derRepresentation
        }

        private let backing: _RSA.Signing.PrivateKey

        public var publicKey: PublicKey {
            // This should never fail since we are creating the public key from the private key
            // which got validated already
            try! .init(backing: self.backing.publicKey)
        }

        /// Creates an ``RSA.PrivateKey`` from a SwiftCrypto private key.
        ///
        /// - Parameter backing: The SwiftCrypto private key.
        /// - Throws: ``RSAError/keySizeTooSmall`` if the key size is less than 2048 bits.
        public init(backing: _RSA.Signing.PrivateKey) throws {
            guard backing.keySizeInBits >= 2048 else {
                throw RSAError.keySizeTooSmall
            }
            self.backing = backing
        }

        /// Creates an``RSA.PrivateKey`` from private key PEM file in String format.
        ///
        /// Private key PEM files look like:
        ///
        ///     -----BEGIN PRIVATE KEY-----
        ///     MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
        ///     ...
        ///     aX4rbSL49Z3dAQn8vQIDAQAB
        ///     -----END PRIVATE KEY-----
        ///
        /// This key can be used to verify and sign JWTs.
        ///
        /// - Parameters:
        ///   - pem: Contents of PEM file.
        /// - Throws: ``RSAError/keySizeTooSmall`` if the key size is less than 2048 bits.
        public init(pem: String) throws {
            try self.init(backing: .init(pemRepresentation: pem))
        }

        /// Creates an``RSA.PrivateKey`` from private key PEM file in Data format.
        ///
        /// Private key PEM files look like:
        ///
        ///     -----BEGIN PRIVATE KEY-----
        ///     MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
        ///     ...
        ///     aX4rbSL49Z3dAQn8vQIDAQAB
        ///     -----END PRIVATE KEY-----
        ///
        /// This key can be used to verify and sign JWTs.
        ///
        /// - Parameters:
        ///   - pem: Contents of PEM file.
        /// - Throws: ``RSAError/keySizeTooSmall`` if the key size is less than 2048 bits.
        public init(pem data: some DataProtocol) throws {
            let string = String(decoding: data, as: UTF8.self)
            try self.init(pem: string)
        }

        /// Initializes a new ``RSA.PrivateKey`` instance with modulus, exponent, and private exponent.
        ///
        /// This convenience initializer creates an RSA key using the modulus, exponent, and private exponent.
        /// All these parameters are expected to be base64 URL encoded strings.
        ///
        /// - Parameters:
        ///   - modulus: The modulus of the RSA key, represented as a base64 URL encoded string.
        ///   - exponent: The exponent of the RSA key, represented as a base64 URL encoded string.
        ///
        /// - Throws:
        ///   - ``JWTError/generic`` with the identifier `RSAKey` if either the modulus or exponent cannot be decoded from their base64 URL encoded strings.
        ///   - ``RSAError/keyInitializationFailure`` if there is a failure in initializing the RSA key, especially when the private key components are involved.
        ///   - ``RSAError/keySizeTooSmall`` if the key size is less than 2048 bits.
        ///
        /// - Note:
        ///   - The provided modulus and exponent are key components for creating RSA public keys.
        ///   - The private exponent is an additional parameter required for creating RSA private keys.
        public init(
            modulus: String,
            exponent: String,
            privateExponent: String
        ) throws {
            guard let n = modulus.base64URLDecodedData() else {
                throw JWTError.generic(identifier: "RSAKey", reason: "Unable to decode base64url modulus")
            }

            guard let e = exponent.base64URLDecodedData() else {
                throw JWTError.generic(identifier: "RSAKey", reason: "Unable to decode base64url exponent")
            }

            guard let d = privateExponent.base64URLDecodedData() else {
                throw JWTError.generic(identifier: "RSAKey", reason: "Unable to decode base64url private exponent")
            }

            var serializer = DER.Serializer()

            guard let privateKeyDER = try Insecure.RSA.calculatePrivateDER(n: n, e: e, d: d) else {
                throw RSAError.keyInitializationFailure
            }
            try privateKeyDER.serialize(into: &serializer)
            let privateKey = try _RSA.Signing.PrivateKey(derRepresentation: serializer.serializedBytes)
            try self.init(backing: privateKey)
        }

        func signature<D: Digest>(for digest: D, padding: _RSA.Signing.Padding) throws -> _RSA.Signing.RSASignature {
            try self.backing.signature(for: digest, padding: padding)
        }
    }
}
