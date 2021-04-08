extension JWTSigner {
    public static func rs256(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(key: key, name: "RS256"))
    }

    public static func rs384(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(key: key, name: "RS384"))
    }

    public static func rs512(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(key: key, name: "RS512"))
    }
}
