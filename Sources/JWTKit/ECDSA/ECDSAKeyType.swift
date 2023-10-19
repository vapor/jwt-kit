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
    @available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
    init(pemRepresentation: String) throws
    @available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
    init<Bytes>(derRepresentation: Bytes) throws where Bytes: RandomAccessCollection, Bytes.Element == UInt8
    var publicKey: PublicKey { get }
    var rawRepresentation: Data { get }
    var x963Representation: Data { get }
    @available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
    var derRepresentation: Data { get }
    @available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
    var pemRepresentation: String { get }
    func signature<D>(for data: D) throws -> Signature where D: DataProtocol
}

public protocol ECDSAPublicKey {
    init<D>(rawRepresentation: D) throws where D: ContiguousBytes
    init<Bytes>(compactRepresentation: Bytes) throws where Bytes: ContiguousBytes
    init<Bytes>(x963Representation: Bytes) throws where Bytes: ContiguousBytes
    @available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, *)
    init<Bytes>(compressedRepresentation: Bytes) throws where Bytes: ContiguousBytes
    @available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
    init(pemRepresentation: String) throws
    @available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
    init<Bytes>(derRepresentation: Bytes) throws where Bytes: RandomAccessCollection, Bytes.Element == UInt8
    init?(_ key: X509.Certificate.PublicKey)
    var compactRepresentation: Data? { get }
    var rawRepresentation: Data { get }
    var x963Representation: Data { get }
    @available(iOS 16.0, macOS 13.0, watchOS 9.0, tvOS 16.0, *)
    var compressedRepresentation: Data { get }
    @available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
    var derRepresentation: Data { get }
    @available(iOS 14.0, macOS 11.0, watchOS 7.0, tvOS 14.0, *)
    var pemRepresentation: String { get }
    func isValidSignature<Signature, Digest>(_ signature: Signature, for data: Digest) throws -> Bool where Signature: DataProtocol, Digest: DataProtocol
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

// struct ECDSAPrivateKeyASN1: DERSerializable {
//     let r: ArraySlice<UInt8>
//     let s: ArraySlice<UInt8>

//     func serialize(into coder: inout DER.Serializer) throws {
//         try coder.appendConstructedNode(identifier: .sequence) { coder in
//             try coder.serialize(self.r)
//             try coder.serialize(self.s)
//         }
//     }
// }
