import JWTKit

extension Insecure.RSA.PrivateKey: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.derRepresentation == rhs.derRepresentation
    }
}

extension Insecure.RSA.PublicKey: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.derRepresentation == rhs.derRepresentation
    }
}
