import Crypto

extension JWTSigner {
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
