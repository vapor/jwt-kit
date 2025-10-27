import Crypto

@_spi(PostQuantum)
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA65.PublicKey: MLDSAPublicKey {
    public typealias MLDSAType = MLDSA65
}

@_spi(PostQuantum)
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA65.PrivateKey: MLDSAPrivateKey {
    public typealias MLDSAType = MLDSA65
}

@_spi(PostQuantum)
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public typealias MLDSA65PublicKey = MLDSA.PublicKey<MLDSA65>

@_spi(PostQuantum)
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public typealias MLDSA65PrivateKey = MLDSA.PrivateKey<MLDSA65>
