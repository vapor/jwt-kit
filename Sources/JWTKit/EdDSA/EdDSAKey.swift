import Foundation
import Crypto

public struct EdDSAKey {
            
    public enum Curve: String, Codable {
        case ed25519 = "Ed25519"
    }
    
    let keyPair: OctetKeyPair
    var publicKey: Data? {
        keyPair.publicKey
    }
    var privateKey: Data? {
        keyPair.privateKey
    }
    let curve: Curve
    
    public init(x: String?, d: String? = nil, curve: Curve = .ed25519) throws {
        try self.init(
            publicKey: x.flatMap { $0.data(using: .utf8) }.map { Data($0.base64URLDecodedBytes()) },
            privateKey: d.flatMap { $0.data(using: .utf8) }.map { Data($0.base64URLDecodedBytes()) },
            curve: curve
        )
    }
    
    public init(publicKey: Data? = nil, privateKey: Data? = nil, curve: Curve = .ed25519) throws {
        try self.init(
            keyPair: try .init(publicKey: publicKey, privateKey: privateKey),
            curve: curve
        )
    }
    
    init(keyPair: OctetKeyPair, curve: Curve = .ed25519) throws {
        self.keyPair = keyPair
        self.curve = curve
    }
    
    public static func generate(curve: Curve = .ed25519) throws -> EdDSAKey {
        switch curve {
        case .ed25519:            
            let key = Curve25519.Signing.PrivateKey()
            return try .init(
                publicKey: key.publicKey.rawRepresentation,
                privateKey: key.rawRepresentation,
                curve: curve
            )
        }
    }
}

