#if canImport(FoundationEssentials)
public import FoundationEssentials
#else
public import Foundation
#endif

/// This protocol represents a key that can be used for signing and verifying MLDSA signatures.
/// Both ``MLDSA/PublicKey`` and ``MLDSA/PrivateKey`` conform to this protocol, which is what
/// ``JWTKeyCollection/add(mldsa:kid:parser:serializer:)`` accepts.
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public protocol MLDSAKey: Sendable {
    /// The MLDSA parameter set the key belongs to, such as `MLDSA65` or `MLDSA87`.
    associatedtype MLDSAType: JWTKit.MLDSAType
}

/// The requirements JWTKit needs from the underlying SwiftCrypto public key backing an ``MLDSA/PublicKey``.
///
/// You shouldn't need to conform your own types to this protocol: the SwiftCrypto `MLDSA65.PublicKey` and
/// `MLDSA87.PublicKey` types already do.
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public protocol MLDSAPublicKey: Sendable {
    /// The MLDSA parameter set the key belongs to.
    associatedtype MLDSAType

    /// Creates a public key from its raw byte representation.
    ///
    /// - Parameter rawRepresentation: The raw bytes of the public key.
    /// - Throws: If the provided bytes aren't a valid public key for the key's parameter set.
    init(rawRepresentation: some DataProtocol) throws

    /// Raw bytes representation of the public key.
    var rawRepresentation: Data { get }

    /// Verifies that the given signature is valid for the given data.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify.
    ///   - data: The data the signature is expected to sign.
    /// - Returns: Whether the signature is valid.
    func isValidSignature<S: DataProtocol, D: DataProtocol>(_ signature: S, for data: D) -> Bool

    /// Verifies that the given signature is valid for the given data within the given context.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify.
    ///   - data: The data the signature is expected to sign.
    ///   - context: The context the signature was produced in. Signatures don't verify across different contexts.
    /// - Returns: Whether the signature is valid.
    func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(
        _ signature: S, for data: D, context: C
    ) -> Bool
}

/// The requirements JWTKit needs from the underlying SwiftCrypto private key backing an ``MLDSA/PrivateKey``.
///
/// You shouldn't need to conform your own types to this protocol: the SwiftCrypto `MLDSA65.PrivateKey` and
/// `MLDSA87.PrivateKey` types already do.
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public protocol MLDSAPrivateKey: Sendable {
    /// The MLDSA parameter set the key belongs to.
    associatedtype MLDSAType

    /// The type of the public key associated with this private key.
    associatedtype PublicKey: MLDSAPublicKey

    /// The 32-byte seed this private key is derived from.
    var seedRepresentation: Data { get }

    /// The public key associated with this private key.
    var publicKey: PublicKey { get }

    /// Creates a private key from the seed it is derived from.
    ///
    /// - Parameters:
    ///   - seedRepresentation: The 32-byte seed the private key is derived from.
    ///   - publicKey: An optional public key to check the derived key against.
    /// - Throws: If the seed isn't valid, or if the provided public key doesn't match the derived one.
    init<D>(seedRepresentation: D, publicKey: PublicKey?) throws where D: DataProtocol

    /// Signs the given data.
    ///
    /// - Parameter data: The data to sign.
    /// - Returns: The signature.
    /// - Throws: If the signature couldn't be produced.
    func signature<D: DataProtocol>(for data: D) throws -> Data

    /// Signs the given data within the given context.
    ///
    /// - Parameters:
    ///   - data: The data to sign.
    ///   - context: The context to produce the signature in. Signatures don't verify across differing contexts.
    /// - Returns: The signature.
    /// - Throws: If the signature couldn't be produced.
    func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data
}
