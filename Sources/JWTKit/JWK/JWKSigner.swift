actor JWKSigner: Sendable {
    let jwk: JWK
    let parser: any JWTParser
    let serializer: any JWTSerializer
    private(set) var signer: JWTSigner?

    init(
        jwk: JWK,
        parser: some JWTParser = DefaultJWTParser(),
        serializer: some JWTSerializer = DefaultJWTSerializer()
    ) throws {
        self.jwk = jwk
        if let algorithm = try jwk.getKey() {
            self.signer = .init(algorithm: algorithm, parser: parser, serializer: serializer)
        } else {
            self.signer = nil
        }
        self.parser = parser
        self.serializer = serializer
    }

    func makeSigner(for algorithm: JWK.Algorithm) throws -> JWTSigner {
        guard let key = try jwk.getKey(for: algorithm) else {
            throw JWTError.invalidJWK(reason: "Unable to create signer with given algorithm")
        }

        let signer = JWTSigner(algorithm: key, parser: parser, serializer: serializer)
        self.signer = signer
        return signer
    }
}
