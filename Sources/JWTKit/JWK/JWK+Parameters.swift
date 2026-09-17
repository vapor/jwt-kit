extension JWK {
    /// The key material a ``JWK`` carries, keyed by the type of key it belongs to.
    ///
    /// This is the storage a ``JWK`` actually holds. The flat, optional members on ``JWK`` are a
    /// compatibility surface computed from it, so nothing inside JWTKit has to reach for them.
    ///
    /// Only the members a key type genuinely requires are non-optional in each case: anything missing
    /// them lands in ``loose(_:)`` instead. Validation stays where it is today, in the code which turns a
    /// key into a signer, so decoding a key set containing one unusable key doesn't fail the whole set.
    enum Parameters: Sendable {
        case rsa(RSA)
        case ec(EC)
        case okp(OKP)

        /// Members which don't (yet) form a complete key of a known type.
        ///
        /// A key lands here when its type is one JWTKit doesn't model, when a member the key type
        /// requires is absent, or when it has been mutated through the flat compatibility members.
        case loose(Members)
    }

    /// An RSA key. `n` and `e` are always present; the rest are only present on private keys.
    struct RSA: Sendable, Equatable {
        var modulus: String
        var exponent: String
        var privateExponent: String?
        var prime1: String?
        var prime2: String?
    }

    /// An elliptic curve key. Both coordinates are always present.
    struct EC: Sendable, Equatable {
        var x: String
        var y: String
        var curve: Curve?
        /// The `d` member, present only on private keys.
        var privateKey: String?
    }

    /// An octet key pair. The public coordinate is always present.
    struct OKP: Sendable, Equatable {
        var x: String
        var curve: Curve?
        /// The `d` member, present only on private keys.
        var privateKey: String?
    }

    /// Every member a JWK can carry, with no guarantee that they form a usable key.
    struct Members: Sendable, Equatable {
        var keyType: KeyType
        var modulus: String?
        var exponent: String?
        var privateExponent: String?
        var prime1: String?
        var prime2: String?
        var x: String?
        var y: String?
        var curve: Curve?

        init(
            keyType: KeyType,
            modulus: String? = nil,
            exponent: String? = nil,
            privateExponent: String? = nil,
            prime1: String? = nil,
            prime2: String? = nil,
            x: String? = nil,
            y: String? = nil,
            curve: Curve? = nil
        ) {
            self.keyType = keyType
            self.modulus = modulus
            self.exponent = exponent
            self.privateExponent = privateExponent
            self.prime1 = prime1
            self.prime2 = prime2
            self.x = x
            self.y = y
            self.curve = curve
        }
    }
}

extension JWK.Members {
    /// Promotes these members to a typed case, when the key type's required members are all present.
    func normalized() -> JWK.Parameters {
        switch self.keyType.backing {
        case .rsa:
            guard let modulus, let exponent else {
                return .loose(self)
            }
            return .rsa(
                .init(
                    modulus: modulus,
                    exponent: exponent,
                    privateExponent: self.privateExponent,
                    prime1: self.prime1,
                    prime2: self.prime2
                ))

        case .ecdsa:
            guard let x, let y else {
                return .loose(self)
            }
            return .ec(.init(x: x, y: y, curve: self.curve, privateKey: self.privateExponent))

        case .octetKeyPair:
            guard let x else {
                return .loose(self)
            }
            return .okp(.init(x: x, curve: self.curve, privateKey: self.privateExponent))

        case .unknown:
            return .loose(self)
        }
    }
}

extension JWK.Parameters {
    /// Flattens back to the member-by-member form the compatibility surface and `Codable` need.
    var members: JWK.Members {
        switch self {
        case .rsa(let rsa):
            .init(
                keyType: .rsa,
                modulus: rsa.modulus,
                exponent: rsa.exponent,
                privateExponent: rsa.privateExponent,
                prime1: rsa.prime1,
                prime2: rsa.prime2
            )

        case .ec(let ec):
            .init(keyType: .ecdsa, privateExponent: ec.privateKey, x: ec.x, y: ec.y, curve: ec.curve)

        case .okp(let okp):
            .init(keyType: .octetKeyPair, privateExponent: okp.privateKey, x: okp.x, curve: okp.curve)

        case .loose(let members):
            members
        }
    }
}
