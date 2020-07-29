internal enum RSAError: Error {
    case privateKeyRequired
    case signFailure
    case keyInitializationFailure
}
