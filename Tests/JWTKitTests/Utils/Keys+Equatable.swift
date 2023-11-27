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

extension ECDSA.PublicKey: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.parameters?.x == rhs.parameters?.x && lhs.parameters?.y == rhs.parameters?.y
    }
}

extension ECDSA.PrivateKey: Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.parameters?.x == rhs.parameters?.x && lhs.parameters?.y == rhs.parameters?.y
    }
}
