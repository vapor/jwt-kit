import _CryptoExtras

extension MLDSA87.PublicKey: MLDSAPublicKey {
    public typealias MLDSAType = MLDSA87
}

extension MLDSA87.PrivateKey: MLDSAPrivateKey {
    public typealias MLDSAType = MLDSA87
}

public typealias MLDSA87PublicKey = MLDSA.PublicKey<MLDSA87>
public typealias MLDSA87PrivateKey = MLDSA.PrivateKey<MLDSA87>
