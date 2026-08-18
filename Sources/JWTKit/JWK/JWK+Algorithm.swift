extension JWK {
    /// The `alg` (algorithm) parameter identifies the algorithm intended for use with the key.
    /// Unkown algorithms are preserved.
    public struct Algorithm: Codable, RawRepresentable, Equatable, Sendable {
        public typealias RawValue = String

        enum Backing: Equatable, Sendable {
            case rs256, rs384, rs512
            case ps256, ps384, ps512
            case es256, es384, es512
            case eddsa
            case rsaOAEP
            case unknown(String)

            var rawValue: String {
                switch self {
                case .rs256: "RS256"
                case .rs384: "RS384"
                case .rs512: "RS512"
                case .ps256: "PS256"
                case .ps384: "PS384"
                case .ps512: "PS512"
                case .es256: "ES256"
                case .es384: "ES384"
                case .es512: "ES512"
                case .eddsa: "EdDSA"
                case .rsaOAEP: "RSA-OAEP"
                case .unknown(let name): name
                }
            }

            init(rawValue: String) {
                switch rawValue {
                case "RS256": self = .rs256
                case "RS384": self = .rs384
                case "RS512": self = .rs512
                case "PS256": self = .ps256
                case "PS384": self = .ps384
                case "PS512": self = .ps512
                case "ES256": self = .es256
                case "ES384": self = .es384
                case "ES512": self = .es512
                case "EdDSA": self = .eddsa
                case "RSA-OAEP": self = .rsaOAEP
                default: self = .unknown(rawValue)
                }
            }
        }

        let backing: Backing

        public var rawValue: String {
            self.backing.rawValue
        }

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
        /// RSA with OAEP
        public static let rsaOAEP = Self(backing: .rsaOAEP)

        /// Represents a algorithm JWTKit doesn't recognise, preserving its name.
        public static func unknown(_ rawValue: String) -> Self { .init(backing: .unknown(rawValue)) }

        init(backing: Backing) {
            self.backing = backing
        }

        /// Creates an algorithm from its rawValue, falling back to `unknown` if it's not recognised.
        ///
        /// > Note: This initialiser is failable due to source compatibility,
        /// > but it doesn't actually ever return `nil`. This should be fixed in the next major.
        public init?(rawValue: String) {
            let backing = Backing(rawValue: rawValue)
            self.init(backing: backing)
        }

        public init(from decoder: any Decoder) throws {
            try self.init(backing: .init(rawValue: decoder.singleValueContainer().decode(String.self)))
        }

        public func encode(to encoder: any Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(self.rawValue)
        }
    }
}
