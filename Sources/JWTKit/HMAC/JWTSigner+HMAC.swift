@_implementationOnly import CJWTKitBoringSSL
import Crypto
import Foundation

extension JWTSigner {
    // MARK: 256

    public static func hs256(key: String) -> JWTSigner {
        self.hs256(key: [UInt8](key.utf8))
    }

    public static func hs256<Key>(key: Key) -> JWTSigner
        where Key: DataProtocol
    {
        let symmetricKey = SymmetricKey(data: key.copyBytes())
        return JWTSigner.hs256(key: symmetricKey)
    }
    
    public static func hs256(key: SymmetricKey) -> JWTSigner {
        return .init(algorithm: HMACSigner<SHA256>(key: key, name: "HS256"))
    }

    // MARK: 384

    public static func hs384(key: String) -> JWTSigner {
        self.hs384(key: [UInt8](key.utf8))
    }

    public static func hs384<Key>(key: Key) -> JWTSigner
        where Key: DataProtocol
    {
        let symmetricKey = SymmetricKey(data: key.copyBytes())
        return JWTSigner.hs384(key: symmetricKey)
    }
    
    public static func hs384(key: SymmetricKey) -> JWTSigner {
        return .init(algorithm: HMACSigner<SHA384>(key: key, name: "HS384"))
    }

    // MARK: 512

    public static func hs512(key: String) -> JWTSigner {
        self.hs512(key: [UInt8](key.utf8))
    }

    public static func hs512<Key>(key: Key) -> JWTSigner
        where Key: DataProtocol
    {
        let symmetricKey = SymmetricKey(data: key.copyBytes())
        return JWTSigner.hs512(key: symmetricKey)
    }
    
    public static func hs512(key: SymmetricKey) -> JWTSigner {
        return .init(algorithm: HMACSigner<SHA512>(key: key, name: "HS512"))
    }
}
