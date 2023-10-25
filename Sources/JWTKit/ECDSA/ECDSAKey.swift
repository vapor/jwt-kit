import Crypto
import Foundation
import SwiftASN1
import X509

public struct ECDSAKey<Curve>: ECDSAKeyType where Curve: ECDSACurveType {
    var curve: ECDSACurve = Curve.curve

    var parameters: ECDSAParameters? {
        guard let privateKey = privateKey else {
            return nil
        }
        let publicKey = privateKey.publicKey
        // 0x04 || x || y
        let x = publicKey.x963Representation[Curve.byteRanges.x].base64EncodedString()
        let y = publicKey.x963Representation[Curve.byteRanges.y].base64EncodedString()
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
        try .init(publicKey: PublicKey(pemRepresentation: string))
    }

    public static func `public`<Data>(pem: Data) throws -> Self
        where Data: DataProtocol
    {
        let string = String(decoding: pem, as: UTF8.self)
        return try self.public(pem: string)
    }

    public static func `private`(pem string: String) throws -> Self {
        try .init(privateKey: PrivateKey(pemRepresentation: string))
    }

    public static func `private`<Data>(pem: Data) throws -> Self
        where Data: DataProtocol
    {
        let string = String(decoding: pem, as: UTF8.self)
        return try self.private(pem: string)
    }

    public init(parameters: ECDSAParameters, privateKey: String? = nil) throws {
        let privateKeyBytes: [UInt8]?
        if
            let privateKey = privateKey,
            let privateKeyData = privateKey.base64URLDecodedData()
        {
            privateKeyBytes = Array(privateKeyData)
        } else {
            privateKeyBytes = nil
        }

        guard
            let x = parameters.x.base64URLDecodedData(),
            let y = parameters.y.base64URLDecodedData()
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

        if privateKey != nil {
            type = .private
        } else if publicKey != nil {
            type = .public
        } else {
            type = .certificate
        }

        self.privateKey = privateKey
        self.publicKey = publicKey
    }
}
