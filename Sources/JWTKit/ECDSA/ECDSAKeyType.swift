import Foundation
import SwiftASN1

public struct ECDSAParameters {
    public let x: String
    public let y: String
}

public protocol ECDSAPrivateKey {
    var pubKey: ECDSAPublicKey { get }
    func signature<D>(for data: D) throws -> Data where D: DataProtocol
}

public protocol ECDSAPublicKey {
    func isValidSignature<Signature, Digest>(_ signature: Signature, for data: Digest) throws -> Bool where Signature: DataProtocol, Digest: DataProtocol
}

public protocol ECDSAKeyType {
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

struct ECDSAPrivateKeyASN1: DERSerializable {
    let r: ArraySlice<UInt8>
    let s: ArraySlice<UInt8>

    func serialize(into coder: inout DER.Serializer) throws {
        try coder.appendConstructedNode(identifier: .sequence) { coder in
            try coder.serialize(self.r)
            try coder.serialize(self.s)
        }
    }
}
