extension JWK {
    /// Supported `kty` key types.
    public struct KeyType: Codable, RawRepresentable, Equatable, Sendable {
        enum Backing: String, Codable {
            case rsa = "RSA"
            case ecdsa = "EC"
            case octetKeyPair = "OKP"
        }

        let backing: Backing

        public var rawValue: String { self.backing.rawValue }

        public static let rsa = Self(backing: .rsa)
        public static let ecdsa = Self(backing: .ecdsa)
        public static let octetKeyPair = Self(backing: .octetKeyPair)

        init(backing: Backing) {
            self.backing = backing
        }

        public init?(rawValue: String) {
            guard let backing = Backing(rawValue: rawValue) else {
                return nil
            }
            self.init(backing: backing)
        }
    }
}

extension JWK {
    /// Intended use of the public key.
    /// https://datatracker.ietf.org/doc/html/rfc7517#section-4.2
    public enum Usage: String, Codable, Sendable {
        case signature
        case encryption
        
        enum CodingKeys: String, CodingKey {
            case signature = "sig"
            case encryption = "enc"
        }
    }
}

extension JWK {
    /// Operations that the key is intended to be used for.
    /// https://datatracker.ietf.org/doc/html/rfc7517#section-4.3
    public enum KeyOperation: String, Codable, Sendable {
        case sign
        case verify
        case encrypt
        case decrypt
        case wrapKey
        case unwrapKey
        case deriveKey
        case deriveBits
    }
}

extension JWK {
    /// The cryptographic algorithm family used with the key.
    /// https://datatracker.ietf.org/doc/html/rfc7517#section-4.4
    public struct Algorithm: Codable, RawRepresentable, Equatable, Sendable {
        enum Backing: String, Codable {
            case rs256 = "RS256"
            case rs384 = "RS384"
            case rs512 = "RS512"
            case ps256 = "PS256"
            case ps384 = "PS384"
            case ps512 = "PS512"
            case es256 = "ES256"
            case es384 = "ES384"
            case es512 = "ES512"
            case eddsa = "EdDSA"
        }

        let backing: Backing

        public var rawValue: String { self.backing.rawValue }

        /// RSA with SHA256
        public static let rs256 = Self(backing: .rs256)
        /// RSA with SHA384
        public static let rs384 = Self(backing: .rs384)
        /// RSA with SHA512
        public static let rs512 = Self(backing: .rs512)
        /// RSA-PSS with SHA256
        public static let ps256 = Self(backing: .ps256)
        /// RSA-PSS with SHA384
        public static let ps384 = Self(backing: .ps384)
        /// RSA-PSS with SHA512
        public static let ps512 = Self(backing: .ps512)
        /// EC with SHA256
        public static let es256 = Self(backing: .es256)
        /// EC with SHA384
        public static let es384 = Self(backing: .es384)
        /// EC with SHA512
        public static let es512 = Self(backing: .es512)
        /// EdDSA
        public static let eddsa = Self(backing: .eddsa)

        init(backing: Backing) {
            self.backing = backing
        }

        public init?(rawValue: String) {
            guard let backing = Backing(rawValue: rawValue) else {
                return nil
            }
            self.init(backing: backing)
        }
    }
}

