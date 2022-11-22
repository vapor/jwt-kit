@_implementationOnly import CJWTKitBoringSSL

extension JWTSigner {
    public static func rs256(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha256(),
            name: "RS256",
            usePSS: false
        ))
    }

    public static func rs384(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha384(),
            name: "RS384",
            usePSS: false
        ))
    }

    public static func rs512(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha512(),
            name: "RS512",
            usePSS: false
        ))
    }

    public static func ps256(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha256(),
            name: "PS256",
            usePSS: true
        ))
    }

    public static func ps384(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha384(),
            name: "PS384",
            usePSS: true
        ))
    }

    public static func ps512(key: RSAKey) -> JWTSigner {
        return .init(algorithm: RSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha512(),
            name: "PS512",
            usePSS: true
        ))
    }
}
