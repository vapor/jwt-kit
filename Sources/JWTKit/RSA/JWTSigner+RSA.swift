@_implementationOnly import CJWTKitBoringSSL

extension JWTSigner {
    public static func rs256(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha256(),
            name: "RS256"
        ))
    }

    public static func rs384(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha384(),
            name: "RS384"
        ))
    }

    public static func rs512(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha512(),
            name: "RS512"
        ))
    }
}
