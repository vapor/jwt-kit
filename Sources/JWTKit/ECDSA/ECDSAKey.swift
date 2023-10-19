import Crypto
import Foundation
import SwiftASN1
import X509

public final class ECDSAKey<Curve>: ECDSAKeyType where Curve: CurveType {
    var curve: ECDSACurve = Curve.curve

    var parameters: ECDSAParameters? {
        guard let privateKey = privateKey else {
            return nil
        }
        let publicKey = privateKey.publicKey
        // 0x04 || x || y
        let x = publicKey.x963Representation[1 ..< 33].base64EncodedString()
        let y = publicKey.x963Representation[33 ..< 65].base64EncodedString()
        return .init(x: x, y: y)
    }

    typealias Signature = Curve.Signature
    typealias PrivateKey = Curve.PrivateKey
    typealias PublicKey = Curve.PrivateKey.PublicKey

    var type: KeyType

    var privateKey: PrivateKey?
    var publicKey: PublicKey?

    public static func generate() throws -> Self {
        let privateKey = PrivateKey()
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

    public static func `private`<Data>(pem: Data) throws -> Self
        where Data: DataProtocol
    {
        let string = String(decoding: pem, as: UTF8.self)
        return try self.private(pem: string)
    }

    public convenience init(parameters: ECDSAParameters, privateKey: String? = nil) throws {
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
            throw JWTError.generic(identifier: "ecCoordinates", reason: "Unable to interpret x and y as base64 encoded data")
        }

        let publicKey = try PublicKey(x963Representation: Data([0x04]) + x + y)

        if let privateKeyBytes = privateKeyBytes {
            guard let privateKey = try? PrivateKey(rawRepresentation: privateKeyBytes) else {
                throw JWTError.generic(identifier: "ecPrivateKey", reason: "Unable to interpret privateKey as ECDSAPrivateKey")
            }
            try self.init(privateKey: privateKey)
        } else {
            try self.init(publicKey: publicKey)
        }
    }

    init(privateKey: PrivateKey? = nil, publicKey: PublicKey? = nil) throws {
        guard privateKey != nil || publicKey != nil else {
            throw ECDSAError.generateKeyFailure
        }
        type = privateKey != nil ? .private : publicKey != nil ? .public : .certificate
        self.privateKey = privateKey
        self.publicKey = publicKey
    }
}
