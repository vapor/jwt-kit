enum ECDSAError: Error {
    case newKeyByCurveFailure
    case generateKeyFailure
    case signFailure
    case noPublicKey
    case noPrivateKey
}
