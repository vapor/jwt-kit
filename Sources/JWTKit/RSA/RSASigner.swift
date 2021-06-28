import struct Foundation.Data
import _CryptoExtras

internal struct RSASigner: JWTAlgorithm {

    let key: RSAKey
    let name: String

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8] where Plaintext : DataProtocol {
        guard let privateKey = key.privateKeyBacking else {
            throw RSAError.privateKeyRequired
        }
        let bytes = try privateKey.signature(for: plaintext).rawRepresentation
        return Array(bytes)
    }

    func verify<Signature, Plaintext>(_ signature: Signature, signs plaintext: Plaintext) throws -> Bool where Signature : DataProtocol, Plaintext : DataProtocol {
        let publicKey: _RSA.Signing.PublicKey
        if let key = self.key.publicKeyBacking {
            publicKey = key
        } else if let key = self.key.privateKeyBacking?.publicKey {
            publicKey = key
        } else {
            // Something bad has gone wrong as we should be able to get into this state
            throw RSAError.keyInitializationFailure
        }
        let rsaSignature = _RSA.Signing.RSASignature(rawRepresentation: signature)
        return try publicKey.isValidSignature(rsaSignature, for: plaintext)
    }
}
