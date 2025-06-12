enum MLDSAError: Error {
    case noPrivateKey
    case noPublicKey
    case failedToSign(Error)
}
