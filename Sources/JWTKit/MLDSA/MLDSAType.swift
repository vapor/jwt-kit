import Crypto

@_spi(PostQuantum)
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public protocol MLDSAType {
    associatedtype PrivateKey: MLDSAPrivateKey

    static var name: String { get }
}

@_spi(PostQuantum)
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA65: MLDSAType {
    public static var name: String { "ML-DSA-65" }
}

@_spi(PostQuantum)
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA87: MLDSAType {
    public static var name: String { "ML-DSA-87" }
}
