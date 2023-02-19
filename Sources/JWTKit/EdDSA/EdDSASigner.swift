import Foundation
import Crypto

internal struct EdDSASigner: JWTAlgorithm {
    let key: EdDSAKey
    let name = "EdDSA"
    
    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8] where Plaintext : DataProtocol {                
        guard let privateKey = key.privateKey else {
            throw  JWTError.signingAlgorithmFailure(EdDSAError.privateKeyMissing)
        }
        
        switch key.curve {
        case .ed25519:
            return try Curve25519.Signing.PrivateKey(
                rawRepresentation: privateKey
            ).signature(
                for: plaintext
            ).copyBytes()
        }
    }
    
    func verify<Signature, Plaintext>(_ signature: Signature, signs plaintext: Plaintext) throws -> Bool where Signature : DataProtocol, Plaintext : DataProtocol {
        switch key.curve {
        case .ed25519:
            return try Curve25519.Signing.PublicKey(
                rawRepresentation: key.publicKey
            ).isValidSignature(
                signature,
                for: plaintext
            )
        }
    }
}
