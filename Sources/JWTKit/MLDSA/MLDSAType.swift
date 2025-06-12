import _CryptoExtras

@_spi(PostQuantum)
public protocol MLDSAType {
    associatedtype PrivateKey: MLDSAPrivateKey

    static var name: String { get }
}

@_spi(PostQuantum)
extension MLDSA65: MLDSAType {
    public static var name: String { "ML-DSA-65" }
}

@_spi(PostQuantum)
extension MLDSA87: MLDSAType {
    public static var name: String { "ML-DSA-87" }
}
