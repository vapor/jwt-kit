import JWTKit
import _CryptoExtras

extension ECDSAKey: Equatable {
    public static func == (lhs: ECDSAKey, rhs: ECDSAKey) -> Bool {
        lhs.parameters?.x == rhs.parameters?.x && lhs.parameters?.y == rhs.parameters?.y
    }
}

extension RSAKey: Equatable {
    public static func == (lhs: RSAKey, rhs: RSAKey) -> Bool {
        // Compare public keys
        if 
            let lhsPublicKey = lhs.publicKey,
            let rhsPublicKey = rhs.publicKey,
            lhsPublicKey != rhsPublicKey
        {
            return false
        }
        
        // Compare private keys
        if 
            let lhsPrivateKey = lhs.privateKey,
            let rhsPrivateKey = rhs.privateKey,
            lhsPrivateKey != rhsPrivateKey
        {
            return false
        }

        // If both public and private keys match or are nil, the keys are equal
        return true
    }
}

extension _RSA.Signing.PrivateKey: Equatable {
    public static func == (lhs: _RSA.Signing.PrivateKey, rhs: _RSA.Signing.PrivateKey) -> Bool {
        lhs.derRepresentation == rhs.derRepresentation
    }
}

extension _RSA.Signing.PublicKey: Equatable {
    public static func == (lhs: _RSA.Signing.PublicKey, rhs: _RSA.Signing.PublicKey) -> Bool {
        lhs.derRepresentation == rhs.derRepresentation
    }
}

