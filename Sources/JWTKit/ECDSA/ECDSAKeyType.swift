import Crypto
import Foundation
import SwiftASN1
import X509

/// A typealias representing the parameters of an ECDSA (Elliptic Curve Digital Signature Algorithm) key.
///
/// This tuple consists of two strings representing the x and y coordinates on the elliptic curve.
/// These coordinates are crucial in defining the public key in ECDSA cryptography.
/// They are typically encoded in Base64 or a similar encoding format.
///
/// The `x` and `y` coordinates are represented as strings for easier handling and conversion,
/// especially when dealing with different encoding and serialization formats like PEM, DER, or others commonly used in cryptographic operations.
///
/// - Parameters:
///   - x: A `String` representing the x-coordinate on the elliptic curve.
///   - y: A `String` representing the y-coordinate on the elliptic curve.
public typealias ECDSAParameters = (x: String, y: String)

public protocol ECDSAPrivateKey: Sendable {
    associatedtype PublicKey: ECDSAPublicKey
    associatedtype Signature: ECDSASignature
    init(compactRepresentable: Bool)
    init(x963Representation: some ContiguousBytes) throws
    init(rawRepresentation: some ContiguousBytes) throws
    init(pemRepresentation: String) throws
    init<Bytes>(derRepresentation: Bytes) throws where Bytes: RandomAccessCollection, Bytes.Element == UInt8
    var publicKey: PublicKey { get }
    var rawRepresentation: Data { get }
    var x963Representation: Data { get }
    var derRepresentation: Data { get }
    var pemRepresentation: String { get }
    func signature(for data: some Digest) throws -> Signature
}

public protocol ECDSAPublicKey: Sendable {
    init(rawRepresentation: some ContiguousBytes) throws
    init(compactRepresentation: some ContiguousBytes) throws
    init(x963Representation: some ContiguousBytes) throws
    init(compressedRepresentation: some ContiguousBytes) throws
    init(pemRepresentation: String) throws
    init<Bytes>(derRepresentation: Bytes) throws where Bytes: RandomAccessCollection, Bytes.Element == UInt8
    init?(_ key: X509.Certificate.PublicKey)
    var compactRepresentation: Data? { get }
    var rawRepresentation: Data { get }
    var x963Representation: Data { get }
    var compressedRepresentation: Data { get }
    var derRepresentation: Data { get }
    var pemRepresentation: String { get }
    func isValidSignature(_ signature: some DataProtocol, for data: some Digest) throws -> Bool
}

public protocol ECDSASignature: Sendable {
    var rawRepresentation: Data { get set }
}

extension ECDSAPrivateKey {
    init(compactRepresentable: Bool = true) {
        self.init(compactRepresentable: compactRepresentable)
    }
}

public protocol ECDSAKeyType: Sendable {
    associatedtype Curve: ECDSACurveType
}
