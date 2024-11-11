import Crypto

extension ECDSA.PublicKey: JWKRepresentable {
    public func toJWKRepresentation(kid: String? = nil) -> JWK {
        let algorithm: JWK.Algorithm =
            switch self.curve {
            case .p256: .es256
            case .p384: .es384
            case .p521: .es512
            default: fatalError("Unsupported curve")
            }
        return .ecdsa(
            algorithm,
            identifier: kid.map { .init(string: $0) },
            x: self.coordinates.x,
            y: self.coordinates.y,
            curve: self.curve
        )
    }
}
