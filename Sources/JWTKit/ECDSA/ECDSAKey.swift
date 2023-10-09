import Foundation
import SwiftASN1

// public struct ECDSACurve {
//     let curve: String

//     static var p256: Self {
//         Self(curve: "P-256")
//     }

//     static var p384: Self {
//         Self(curve: "P-384")
//     }

//     static var p521: Self {
//         Self(curve: "P-521")
//     }

//     static var ed25519: Self {
//         Self(curve: "Ed25519")
//     }

//     static var ed448: Self {
//         Self(curve: "Ed448")
//     }
// }

public enum ECDSACurve: String {
    case p256 = "P-256"
    case p384 = "P-384"
    case p521 = "P-521"
    case ed25519 = "Ed25519"
    case ed448 = "Ed448"
}

extension ECDSACurve: Equatable {}

public struct ECDSAParameters {
    public let r: String
    public let s: String
}

public protocol ECDSAPrivateKey {
    var pubKey: ECDSAPublicKey { get }
    func signature<D>(for data: D) throws -> Data where D: DataProtocol
}

public protocol ECDSAPublicKey {
    func isValidSignature<D>(_ signature: Data, for data: D) throws -> Bool where D: DataProtocol
}

public protocol ECDSAKey {
    associatedtype PrivateKey: ECDSAPrivateKey
    associatedtype PublicKey: ECDSAPublicKey

    var curve: ECDSACurve { get }
    var privateKey: PrivateKey? { get }
    var publicKey: PublicKey? { get }

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
