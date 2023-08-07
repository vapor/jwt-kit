internal enum RSAError: Error {
    case privateKeyRequired
    case signFailure(_ error: Error)
    case keyInitializationFailure
}
