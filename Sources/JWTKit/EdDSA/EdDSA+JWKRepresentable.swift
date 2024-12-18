import Crypto

extension EdDSA.PublicKey: JWKRepresentable {
    public func toJWKRepresentation(
        keyIdentifier: JWKIdentifier? = nil,
        use: JWK.Usage? = nil,
        keyOperations: [JWK.KeyOperation]? = nil,
        x509URL: String? = nil,
        x509CertificateChain: [String]? = nil,
        x509SHA1Thumbprint: String? = nil,
        x509SHA256Thumbprint: String? = nil
    ) -> JWK {
        .init(
            keyType: .octetKeyPair,
            algorithm: .eddsa,
            keyIdentifier: keyIdentifier,
            use: use,
            keyOperations: keyOperations,
            x509URL: x509URL,
            x509CertificateChain: x509CertificateChain,
            x509CertificateSHA1Thumbprint: x509SHA1Thumbprint,
            x509CertificateSHA256Thumbprint: x509SHA256Thumbprint,
            x: self.rawRepresentation.base64EncodedString(),
            curve: .eddsa(self.curve)
        )
    }
}
