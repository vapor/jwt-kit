extension JWTSigner {
    public static let unsecuredNone: JWTSigner = .init(algorithm: UnsecuredNoneSigner())
}
