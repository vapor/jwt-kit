enum MLDSAError: Error {
    case noPrivateKey
    case failedToSign(Error)
}
