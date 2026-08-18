import Crypto

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA65.PublicKey: MLDSAPublicKey {
    public typealias MLDSAType = MLDSA65
}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA65.PrivateKey: MLDSAPrivateKey {
    public typealias MLDSAType = MLDSA65
}

/// An MLDSA public key using the `MLDSA65` parameter set, which signs and verifies `ML-DSA-65` tokens.
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public typealias MLDSA65PublicKey = MLDSA.PublicKey<MLDSA65>

/// An MLDSA private key using the `MLDSA65` parameter set, which signs and verifies `ML-DSA-65` tokens.
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public typealias MLDSA65PrivateKey = MLDSA.PrivateKey<MLDSA65>
