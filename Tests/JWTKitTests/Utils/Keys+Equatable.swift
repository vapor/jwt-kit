import JWTKit

#if compiler(<6)
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
#else
extension Insecure.RSA.PrivateKey: @retroactive Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.derRepresentation == rhs.derRepresentation
    }
}

extension Insecure.RSA.PublicKey: @retroactive Equatable {
    public static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.derRepresentation == rhs.derRepresentation
    }
}
#endif
