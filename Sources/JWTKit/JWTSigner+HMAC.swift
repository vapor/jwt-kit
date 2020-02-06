import Crypto
import Foundation

extension JWTSigner {
    // MARK: HMAC

    public static func hs256(key: SymmetricKey) -> JWTSigner {
        return .init(algorithm: HMACSigner<SHA256>(key: key, name: "HS256"))
    }
    
    public static func hs256(key: [UInt8]) -> JWTSigner {
        let symmetricKey = SymmetricKey(data: key)
        return JWTSigner.hs256(key: symmetricKey)
    }
    
    public static func hs384(key: SymmetricKey) -> JWTSigner {
        return .init(algorithm: HMACSigner<SHA384>(key: key, name: "HS384"))
    }
    
    public static func hs384(key: [UInt8]) -> JWTSigner {
        let symmetricKey = SymmetricKey(data: key)
        return JWTSigner.hs384(key: symmetricKey)
    }
    
    public static func hs512(key: SymmetricKey) -> JWTSigner {
        return .init(algorithm: HMACSigner<SHA512>(key: key, name: "HS512"))
    }
    
    public static func hs512(key: [UInt8]) -> JWTSigner {
        let symmetricKey = SymmetricKey(data: key)
        return JWTSigner.hs512(key: symmetricKey)
    }
}

// MARK: Private

private enum HMACError: Error {
    case initializationFailure
    case updateFailure
    case finalizationFailure
}

private struct HMACSigner<SHA_TYPE>: JWTAlgorithm where SHA_TYPE: HashFunction {
    let key: SymmetricKey
    let name: String
    
    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        let authentication = Crypto.HMAC<SHA_TYPE>.authenticationCode(for: plaintext, using: self.key)
        #warning("Change return type to Data")
        return Data(authentication).copyBytes()
    }
}
