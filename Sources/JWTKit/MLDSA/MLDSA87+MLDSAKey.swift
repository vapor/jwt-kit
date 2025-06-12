import _CryptoExtras

@_spi(PostQuantum)
extension MLDSA87.PublicKey: MLDSAPublicKey {
    public typealias MLDSAType = MLDSA87
}

@_spi(PostQuantum)
extension MLDSA87.PrivateKey: MLDSAPrivateKey {
    public typealias MLDSAType = MLDSA87
}

@_spi(PostQuantum) public typealias MLDSA87PublicKey = MLDSA.PublicKey<MLDSA87>
@_spi(PostQuantum) public typealias MLDSA87PrivateKey = MLDSA.PrivateKey<MLDSA87>
