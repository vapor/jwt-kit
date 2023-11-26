import JWTKit

extension RSA.PrivateKey: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.derRepresentation == rhs.derRepresentation
    }
}

extension RSA.PublicKey: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.derRepresentation == rhs.derRepresentation
    }
}
