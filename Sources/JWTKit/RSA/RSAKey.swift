@preconcurrency import _CryptoExtras
import Crypto
import Foundation
import SwiftASN1
import X509

/// A structure that represents an RSA key which can be used for cryptographic operations.
///
/// ``RSAKey`` provides functionality to create RSA keys from different sources such as PEM files or specific key components.
/// It supports both public and private RSA keys.
public struct RSAKey: Sendable {
    /// Exports the current public key as a PEM encoded string.
    ///
    /// - Returns: A PEM encoded string representation of the key.
    public var publicKeyPEMRepresentation: String {
        publicKey.pemRepresentation
    }

    /// Exports the current private key as a PEM encoded string.
    ///
    /// - Throws: If the key is not a private key.
    /// - Returns: A PEM encoded string representation of the key.
    public var privateKeyPEMRepresentation: String {
        get throws {
            guard let privateKey else {
                throw RSAError.privateKeyRequired
            }
            return privateKey.pemRepresentation
        }
    }
    
    /// Creates an ``RSAKey`` from public key PEM file.
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
    public static func `public`(pem string: String) throws -> RSAKey {
        do {
            return try RSAKey(publicKey: .init(pemRepresentation: string))
        } catch CryptoKitError.incorrectParameterSize {
            throw RSAError.keySizeTooSmall
        }
    }

    /// Creates an ``RSAKey`` from public key PEM file.
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
    public static func `public`(pem data: some DataProtocol) throws -> RSAKey {
        let string = String(decoding: data, as: UTF8.self)
        return try self.public(pem: string)
    }

    /// Creates an ``RSAKey`` from public certificate PEM file.
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
    public static func certificate(pem string: String) throws -> RSAKey {
        let cert = try X509.Certificate(pemEncoded: string)
        do {
            guard let publicKey = _RSA.Signing.PublicKey(cert.publicKey) else {
                throw RSAError.keyInitializationFailure
            }
            return RSAKey(publicKey: publicKey)
        } catch CryptoKitError.incorrectParameterSize {
            throw RSAError.keySizeTooSmall
        }
    }

    /// Creates  an``RSAKey`` from public certificate PEM file.
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
    public static func certificate(pem data: some DataProtocol) throws -> RSAKey {
        let string = String(decoding: data, as: UTF8.self)
        return try certificate(pem: string)
    }

    /// Creates an``RSAKey`` from private key PEM file.
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
    public static func `private`(pem string: String) throws -> RSAKey {
        do {
            return try RSAKey(privateKey: .init(pemRepresentation: string))
        } catch CryptoKitError.incorrectParameterSize {
            throw RSAError.keySizeTooSmall
        }
    }

    /// Creates an ``RSAKey`` from private key pem file.
    ///
    /// Private key pem files look like:
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
    ///     - pem: Contents of pem file.
    public static func `private`(pem data: some DataProtocol) throws -> RSAKey {
        let string = String(decoding: data, as: UTF8.self)
        return try self.private(pem: string)
    }

    let type: KeyType

    package let publicKey: _RSA.Signing.PublicKey
    package let privateKey: _RSA.Signing.PrivateKey?

    init(publicKey: _RSA.Signing.PublicKey) {
        self.type = .public
        self.publicKey = publicKey
        self.privateKey = nil
    }

    init(privateKey: _RSA.Signing.PrivateKey) {
        self.type = .private
        self.publicKey = privateKey.publicKey
        self.privateKey = privateKey
    }

    /// Initializes a new RSA key instance with modulus, exponent, and an optional private exponent.
    ///
    /// This convenience initializer creates an RSA key using the modulus, exponent, and an optional private exponent.
    /// All these parameters are expected to be base64 URL encoded strings.
    /// If the private exponent is provided, the initializer creates an RSA private key. Otherwise, it initializes an RSA public key.
    ///
    /// - Parameters:
    ///   - modulus: The modulus of the RSA key, represented as a base64 URL encoded string.
    ///   - exponent: The exponent of the RSA key, represented as a base64 URL encoded string.
    ///   - privateExponent: An optional base64 URL encoded string representing the private exponent of the RSA key. If this parameter is nil, only a public key is generated. Defaults to `nil`.
    ///
    /// - Throws:
    ///   - ``JWTError/generic`` with the identifier `RSAKey`` if either the modulus or exponent cannot be decoded from their base64 URL encoded strings.
    ///   - ``RSAError/keyInitializationFailure`` if there is a failure in initializing the RSA key, especially when the private key components are involved.
    ///
    /// - Note:
    ///   - The provided modulus and exponent are key components for creating RSA public keys.
    ///   - The private exponent is an additional parameter required for creating RSA private keys.
    public init(
        modulus: String,
        exponent: String,
        privateExponent: String? = nil
    ) throws {
        // Helper function to decode base64URL strings
        func decode(_ string: String) throws -> Data {
            guard let data = string.base64URLDecodedData() else {
                throw JWTError.generic(identifier: "RSAKey", reason: "Unable to decode base64url string: \(string)")
            }
            return data
        }

        // Decoding input strings
        let n = try decode(modulus)
        let e = try decode(exponent)
        let d = try privateExponent.map(decode)

        // Serializer to be used for DER serialization
        var serializer = DER.Serializer()

        // Creating key based on the presence of a private exponent
        if let d, let privateKeyDER = try? RSAKey.calculatePrivateDER(n: n, e: e, d: d)
        {
            try privateKeyDER.serialize(into: &serializer)
            let privateKey = try _RSA.Signing.PrivateKey(derRepresentation: serializer.serializedBytes)
            self.init(privateKey: privateKey)
        } else if let publicKeyDER = try? RSAKey.calculateDER(n: n, e: e) {
            try publicKeyDER.serialize(into: &serializer)
            let publicKey = try _RSA.Signing.PublicKey(derRepresentation: serializer.serializedBytes)
            self.init(publicKey: publicKey)
        } else {
            throw RSAError.keyInitializationFailure
        }
    }
}

extension RSAKey: Equatable {
    public static func == (lhs: RSAKey, rhs: RSAKey) -> Bool {
        // Compare public keys
        guard lhs.publicKey.derRepresentation == rhs.publicKey.derRepresentation else {
            return false
        }
        
        // Compare private keys
        if 
            let lhsPrivateKey = lhs.privateKey,
            let rhsPrivateKey = rhs.privateKey,
            lhsPrivateKey.derRepresentation != rhsPrivateKey.derRepresentation
        {
            return false
        }

        // If both public and private keys match or are nil, the keys are equal
        return true
    }
}
