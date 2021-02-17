@_implementationOnly import CJWTKitBoringSSL

extension JWTSigner {
    public static func es256(key: ECDSAKey) -> JWTSigner {
        return .init(algorithm: ECDSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha256(),
            name: "ES256"
        ))
    }

    public static func es384(key: ECDSAKey) -> JWTSigner {
        return .init(algorithm: ECDSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha384(),
            name: "ES384"
        ))
    }

    public static func es512(key: ECDSAKey) -> JWTSigner {
        return .init(algorithm: ECDSASigner(
            key: key,
            algorithm: CJWTKitBoringSSL_EVP_sha512(),
            name: "ES512"
        ))
    }
}
