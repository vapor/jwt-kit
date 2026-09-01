public import Crypto

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA87.PublicKey: MLDSAPublicKey {
    public typealias MLDSAType = MLDSA87
}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA87.PrivateKey: MLDSAPrivateKey {
    public typealias MLDSAType = MLDSA87
}

/// An MLDSA public key using the `MLDSA87` parameter set, which signs and verifies `ML-DSA-87` tokens.
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public typealias MLDSA87PublicKey = MLDSA.PublicKey<MLDSA87>

/// An MLDSA private key using the `MLDSA87` parameter set, which signs and verifies `ML-DSA-87` tokens.
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public typealias MLDSA87PrivateKey = MLDSA.PrivateKey<MLDSA87>
