import Foundation
import Crypto

public struct EdDSAKey {
            
    public enum Curve: String, Codable {
        case ed25519 = "Ed25519"
    }
    
    let keyPair: OctetKeyPair
    var publicKey: Data {
        keyPair.publicKey
    }
    var privateKey: Data? {
        keyPair.privateKey
    }
    let curve: Curve
         
    public static func `public`(x: String, curve: Curve) throws -> EdDSAKey {
        
        guard let xData = x.data(using: .utf8), !xData.isEmpty else {
            throw EdDSAError.publicKeyMissing
        }
        
        return try EdDSAKey(
            keyPair: .`public`(
                x: Data(xData.base64URLDecodedBytes())
            ),
            curve: curve
        )
    }
    
    public static func `private`(x: String, d: String, curve: Curve) throws -> EdDSAKey {
        guard let xData = x.data(using: .utf8), !xData.isEmpty else {
            throw EdDSAError.publicKeyMissing
        }
        
        guard let dData = d.data(using: .utf8), !dData.isEmpty else {
            throw EdDSAError.privateKeyMissing
        }
        
        
        return try EdDSAKey(
            keyPair: .`private`(
                x: Data(xData.base64URLDecodedBytes()),
                d: Data(dData.base64URLDecodedBytes())
            ),
            curve: curve
        )
    }
    
    init(keyPair: OctetKeyPair, curve: Curve) throws {
        self.keyPair = keyPair
        self.curve = curve
    }
    
    public static func generate(curve: Curve) throws -> EdDSAKey {
        switch curve {
        case .ed25519:            
            let key = Curve25519.Signing.PrivateKey()
            return try .init(
                keyPair: .`private`(
                    x: key.publicKey.rawRepresentation,
                    d: key.rawRepresentation),
                curve: curve
            )
        }
    }
}

