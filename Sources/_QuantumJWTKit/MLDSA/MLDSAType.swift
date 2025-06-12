import _CryptoExtras

public protocol MLDSAType {
    associatedtype PrivateKey: MLDSAPrivateKey

    static var name: String { get }
}

extension MLDSA65: MLDSAType {
    public static var name: String { "ML-DSA-65" }
}

extension MLDSA87: MLDSAType {
    public static var name: String { "ML-DSA-87" }
}
