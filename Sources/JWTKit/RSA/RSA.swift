@preconcurrency import _CryptoExtras
import Crypto
import Foundation
import SwiftASN1
import X509

public enum RSA: Sendable {}
public protocol RSAKey: Sendable {}

public extension RSA {
    struct PublicKey: RSAKey {
        // Exports the current public key as a PEM encoded string.
        ///
        /// - Returns: A PEM encoded string representation of the key.
        public var pemRepresentation: String {
            backing.pemRepresentation
        }

        package let backing: _RSA.Signing.PublicKey

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
        /// - parameters:
        ///     - pem: Contents of PEM file.
        public init(pem: String) throws {
            do {
                try self.init(backing: .init(pemRepresentation: pem))
            } catch CryptoKitError.incorrectParameterSize {
                throw RSAError.keySizeTooSmall
            }
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
        /// - parameters:
        ///     - pem: Contents of PEM file.
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
        /// - parameters:
        ///     - pem: Contents of pem file.
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
        /// - parameters:
        ///     - pem: Contents of PEM file.
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
            let n = try decode(modulus)
            let e = try decode(exponent)

            var serializer = DER.Serializer()

            let publicKeyDER = try RSA.calculateDER(n: n, e: e)
            try publicKeyDER.serialize(into: &serializer)
            let publicKey = try _RSA.Signing.PublicKey(derRepresentation: serializer.serializedBytes)
            self.init(backing: publicKey)
        }

        package init(backing: _RSA.Signing.PublicKey) {
            self.backing = backing
        }

        func isValidSignature<D: Digest>(_ signature: _RSA.Signing.RSASignature, for digest: D, padding: _RSA.Signing.Padding) -> Bool {
            return self.backing.isValidSignature(signature, for: digest, padding: padding)
        }
    }
}

public extension RSA {
    struct PrivateKey: RSAKey {
        /// Exports the current private key as a PEM encoded string.
        ///
        /// - Throws: If the key is not a private key.
        /// - Returns: A PEM encoded string representation of the key.
        public var pemRepresentation: String {
            backing.pemRepresentation
        }

        package let backing: _RSA.Signing.PrivateKey
        package let publicKey: PublicKey

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
        /// - parameters:
        ///     - pem: Contents of PEM file.
        public init(pem: String) throws {
            do {
                try self.init(backing: .init(pemRepresentation: pem))
            } catch CryptoKitError.incorrectParameterSize {
                throw RSAError.keySizeTooSmall
            }
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
        /// - parameters:
        ///     - pem: Contents of PEM file.
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
        ///
        /// - Note:
        ///   - The provided modulus and exponent are key components for creating RSA public keys.
        ///   - The private exponent is an additional parameter required for creating RSA private keys.
        public init(
            modulus: String,
            exponent: String,
            privateExponent: String
        ) throws {
            let n = try decode(modulus)
            let e = try decode(exponent)
            let d = try decode(privateExponent)

            var serializer = DER.Serializer()

            guard let privateKeyDER = try RSA.calculatePrivateDER(n: n, e: e, d: d) else {
                throw RSAError.keyInitializationFailure
            }
            try privateKeyDER.serialize(into: &serializer)
            let privateKey = try _RSA.Signing.PrivateKey(derRepresentation: serializer.serializedBytes)
            self.init(backing: privateKey)
        }

        init(backing: _RSA.Signing.PrivateKey) {
            self.backing = backing
            self.publicKey = .init(backing: backing.publicKey)
        }

        func signature<D: Digest>(for digest: D, padding: _RSA.Signing.Padding) throws -> _RSA.Signing.RSASignature {
            try self.backing.signature(for: digest, padding: padding)
        }
    }
}

extension RSA {
    // Helper function to decode base64URL strings
    private static func decode(_ string: String) throws -> Data {
        guard let data = string.base64URLDecodedData() else {
            throw JWTError.generic(identifier: "RSAKey", reason: "Unable to decode base64url string: \(string)")
        }
        return data
    }
}

extension RSA.PrivateKey: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.backing.derRepresentation == rhs.backing.derRepresentation
    }
}

extension RSA.PublicKey: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.backing.derRepresentation == rhs.backing.derRepresentation
    }
}
