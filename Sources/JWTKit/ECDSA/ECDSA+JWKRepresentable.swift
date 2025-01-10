import Crypto

extension ECDSA.PublicKey: JWKRepresentable {
    public func toJWKRepresentation(
        keyIdentifier: JWKIdentifier? = nil,
        use: JWK.Usage? = nil,
        keyOperations: [JWK.KeyOperation]? = nil,
        x509URL: String? = nil,
        x509CertificateChain: [String]? = nil,
        x509SHA1Thumbprint: String? = nil,
        x509SHA256Thumbprint: String? = nil
    ) -> JWK {
        let algorithm: JWK.Algorithm =
            switch self.curve {
            case .p256: .es256
            case .p384: .es384
            case .p521: .es512
            default: fatalError("Unsupported curve")
            }
        return .init(
            keyType: .ecdsa,
            algorithm: algorithm,
            keyIdentifier: keyIdentifier,
            use: use,
            keyOperations: keyOperations,
            x509URL: x509URL,
            x509CertificateChain: x509CertificateChain,
            x509CertificateSHA1Thumbprint: x509SHA1Thumbprint,
            x509CertificateSHA256Thumbprint: x509SHA256Thumbprint,
            x: self.coordinates.x,
            y: self.coordinates.y,
            curve: .ecdsa(self.curve)
        )
    }
}
