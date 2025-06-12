import _CryptoExtras

@_spi(PostQuantum)
extension MLDSA65.PublicKey: MLDSAPublicKey {
    public typealias MLDSAType = MLDSA65
}

@_spi(PostQuantum)
extension MLDSA65.PrivateKey: MLDSAPrivateKey {
    public typealias MLDSAType = MLDSA65
}

@_spi(PostQuantum) public typealias MLDSA65PublicKey = MLDSA.PublicKey<MLDSA65>
@_spi(PostQuantum) public typealias MLDSA65PrivateKey = MLDSA.PrivateKey<MLDSA65>
