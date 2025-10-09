import Crypto

@_spi(PostQuantum)
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA87.PublicKey: MLDSAPublicKey {
    public typealias MLDSAType = MLDSA87
}

@_spi(PostQuantum)
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA87.PrivateKey: MLDSAPrivateKey {
    public typealias MLDSAType = MLDSA87
}

@_spi(PostQuantum)
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public typealias MLDSA87PublicKey = MLDSA.PublicKey<MLDSA87>

@_spi(PostQuantum)
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public typealias MLDSA87PrivateKey = MLDSA.PrivateKey<MLDSA87>
