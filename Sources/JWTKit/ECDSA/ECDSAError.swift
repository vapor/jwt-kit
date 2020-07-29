internal enum ECDSAError: Error {
    case newKeyByCurveFailure
    case generateKeyFailure
    case signFailure
}
