enum RSAError: Error {
    case privateKeyRequired
    case publicKeyRequired
    case signFailure(_ error: Error)
    case keyInitializationFailure
    case keySizeTooSmall
}
