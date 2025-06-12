import _CryptoExtras

extension MLDSA65.PublicKey: MLDSAPublicKey {
    public typealias MLDSAType = MLDSA65
}

extension MLDSA65.PrivateKey: MLDSAPrivateKey {
    public typealias MLDSAType = MLDSA65
}

public typealias MLDSA65PublicKey = MLDSA.PublicKey<MLDSA65>
public typealias MLDSA65PrivateKey = MLDSA.PrivateKey<MLDSA65>
