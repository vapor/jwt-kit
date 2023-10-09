import Crypto
import Foundation
import SwiftASN1
import X509

public final class P256Key: ECDSAKey {
    public var curve: ECDSACurve = .p256

    public typealias Signature = P256.Signing.ECDSASignature
    public typealias PrivateKey = P256.Signing.PrivateKey
    public typealias PublicKey = P256.Signing.PublicKey

    var type: KeyType

    public var privateKey: PrivateKey?
    public var publicKey: PublicKey?

    public static func generate() throws -> Self {
        let privateKey = P256.Signing.PrivateKey()
        return try .init(privateKey: privateKey, publicKey: privateKey.publicKey)
    }

    public static func certificate(pem string: String) throws -> Self {
        let cert = try X509.Certificate(pemEncoded: string)
        guard let publicKey = PublicKey(cert.publicKey) else {
            throw ECDSAError.generateKeyFailure
        }
        return try .init(publicKey: publicKey)
    }

    public static func certificate<Data>(pem: Data) throws -> Self
        where Data: DataProtocol
    {
        let string = String(decoding: pem, as: UTF8.self)
        return try certificate(pem: string)
    }

    public static func `public`(pem string: String) throws -> Self {
        if #available(macOS 11.0, *) {
            return try .init(publicKey: PublicKey(pemRepresentation: string))
        } else {
            let publicKey = try X509.Certificate.PublicKey(pemEncoded: string)
            guard let p256PublicKey = PublicKey(publicKey) else {
                throw ECDSAError.generateKeyFailure
            }
            return try .init(publicKey: p256PublicKey)
        }
    }

    public static func `public`<Data>(pem: Data) throws -> Self
        where Data: DataProtocol
    {
        let string = String(decoding: pem, as: UTF8.self)
        return try self.public(pem: string)
    }

    public static func `private`(pem string: String) throws -> Self {
        if #available(macOS 11.0, *) {
            return try .init(privateKey: PrivateKey(pemRepresentation: string))
        } else {
            let der = string.replacingOccurrences(of: "-----BEGIN PRIVATE KEY-----", with: "")
                .replacingOccurrences(of: "-----END PRIVATE KEY-----", with: "")
                .replacingOccurrences(of: "\n", with: "")
            guard let derData = Foundation.Data(base64Encoded: der) else {
                throw JWTError.signingAlgorithmFailure(ECDSAError.generateKeyFailure)
            }
            return try .init(privateKey: PrivateKey(x963Representation: derData))
        }
    }

    public static func `private`<Data>(pem: Data) throws -> P256Key
        where Data: DataProtocol
    {
        let string = String(decoding: pem, as: UTF8.self)
        return try self.private(pem: string)
    }

    public convenience init(parameters: Parameters, privateKey: String? = nil) throws {
        let privateKeyBytes: [UInt8]?
        if let privateKey = privateKey, let privateKeyData = Data(base64Encoded: privateKey) {
            privateKeyBytes = Array(privateKeyData)
        } else {
            privateKeyBytes = nil
        }

        guard
            let x = Data(base64Encoded: parameters.x),
            let y = Data(base64Encoded: parameters.y)
        else {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "Unable to interpret x or y as Data")
        }

        let publicKey = try PublicKey(x963Representation: x + y)

        if let privateKeyBytes = privateKeyBytes {
            guard let privateKey = try? PrivateKey(rawRepresentation: privateKeyBytes) else {
                throw JWTError.generic(identifier: "ecPrivateKey", reason: "Unable to interpret privateKey as ECDSAPrivateKey")
            }
            try self.init(privateKey: privateKey)
        } else {
            try self.init(publicKey: publicKey)
        }
    }

    public init(privateKey: PrivateKey? = nil, publicKey: PublicKey? = nil) throws {
        guard privateKey != nil || publicKey != nil else {
            throw ECDSAError.generateKeyFailure
        }
        type = privateKey != nil ? .private : publicKey != nil ? .public : .certificate
        self.privateKey = privateKey
        self.publicKey = publicKey
    }

    public struct Parameters {
        let x: String
        let y: String
    }
}

extension P256.Signing.PrivateKey: ECDSAPrivateKey {
    public var pubKey: ECDSAPublicKey {
        publicKey
    }

    public func signature<D>(for data: D) throws -> Data where D: DataProtocol {
        try signature(for: data).rawRepresentation
    }
}

extension P256.Signing.PublicKey: ECDSAPublicKey {
    public func isValidSignature<D>(_ signature: Data, for data: D) throws -> Bool where D: DataProtocol {
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        return isValidSignature(signature, for: data)
    }
}
