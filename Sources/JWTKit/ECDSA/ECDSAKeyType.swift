import Crypto
import Foundation
import SwiftASN1
import X509

public struct ECDSAParameters {
    public let x: String
    public let y: String
}

public protocol ECDSAPrivateKey {
    associatedtype PublicKey: ECDSAPublicKey
    associatedtype Signature: ECDSASignature
    init(compactRepresentable: Bool)
    init<Bytes>(x963Representation: Bytes) throws where Bytes: ContiguousBytes
    init<Bytes>(rawRepresentation: Bytes) throws where Bytes: ContiguousBytes
    init(pemRepresentation: String) throws
    init<Bytes>(derRepresentation: Bytes) throws where Bytes: RandomAccessCollection, Bytes.Element == UInt8
    var publicKey: PublicKey { get }
    var rawRepresentation: Data { get }
    var x963Representation: Data { get }
    var derRepresentation: Data { get }
    var pemRepresentation: String { get }
    func signature<D>(for data: D) throws -> Signature where D: Digest
}

public protocol ECDSAPublicKey {
    init<D>(rawRepresentation: D) throws where D: ContiguousBytes
    init<Bytes>(compactRepresentation: Bytes) throws where Bytes: ContiguousBytes
    init<Bytes>(x963Representation: Bytes) throws where Bytes: ContiguousBytes
    init<Bytes>(compressedRepresentation: Bytes) throws where Bytes: ContiguousBytes
    init(pemRepresentation: String) throws
    init<Bytes>(derRepresentation: Bytes) throws where Bytes: RandomAccessCollection, Bytes.Element == UInt8
    init?(_ key: X509.Certificate.PublicKey)
    var compactRepresentation: Data? { get }
    var rawRepresentation: Data { get }
    var x963Representation: Data { get }
    var compressedRepresentation: Data { get }
    var derRepresentation: Data { get }
    var pemRepresentation: String { get }
    func isValidSignature<Signature, D>(_ signature: Signature, for data: D) throws -> Bool where Signature: DataProtocol, D: Digest
}

public protocol ECDSASignature {
    var rawRepresentation: Data { get set }
}

extension ECDSAPrivateKey {
    init(compactRepresentable: Bool = true) {
        self.init(compactRepresentable: compactRepresentable)
    }
}

protocol ECDSAKeyType {
    associatedtype PrivateKey: ECDSAPrivateKey
    associatedtype PublicKey: ECDSAPublicKey

    var curve: ECDSACurve { get }
    var privateKey: PrivateKey? { get }
    var publicKey: PublicKey? { get }
    var parameters: ECDSAParameters? { get }

    static func generate() throws -> Self
    static func certificate(pem string: String) throws -> Self
    static func certificate<Data>(pem data: Data) throws -> Self where Data: DataProtocol
    static func `private`(pem string: String) throws -> Self
    static func `private`<Data>(pem data: Data) throws -> Self where Data: DataProtocol
    static func `public`(pem string: String) throws -> Self
    static func `public`<Data>(pem data: Data) throws -> Self where Data: DataProtocol
}
