enum RSAError: Error {
    case privateKeyRequired
    case publicKeyRequired
    case signFailure(_ error: any Error)
    case keyInitializationFailure
    case keySizeTooSmall
}
