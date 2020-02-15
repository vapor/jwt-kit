import CJWTKitCrypto

extension JWTSigner {
    public static func hs256<Key>(key: Key) -> JWTSigner
        where Key: DataProtocol
    {
        return .init(algorithm: HMACSigner(
            key: key.copyBytes(),
            algorithm: convert(EVP_sha256()),
            name: "HS256"
        ))
    }

    public static func hs384<Key>(key: Key) -> JWTSigner
        where Key: DataProtocol
    {
        return .init(algorithm: HMACSigner(
            key: key.copyBytes(),
            algorithm: convert(EVP_sha384()),
            name: "HS384"
        ))
    }

    public static func hs512<Key>(key: Key) -> JWTSigner
        where Key: DataProtocol
    {
        return .init(algorithm: HMACSigner(
            key: key.copyBytes(),
            algorithm: convert(EVP_sha512()),
            name: "HS512"
        ))
    }
}
