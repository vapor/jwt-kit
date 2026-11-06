extension JWK {
    /// The `kty` (key type) parameter identifies the cryptographic algorithm family used with the key,
    /// such as `RSA` or `EC`. The `kty` value is a case-sensitive string.
    ///
    /// Key types which JWTKit doesn't recognise are preserved rather than rejected. This is what stops a
    /// single unsupported key from failing the decoding of an entire key set, as RFC 7517 § 5 requires:
    /// *"Implementations SHOULD ignore JWKs within a JWK Set that use `kty` values that are not understood"*.
    public struct KeyType: Codable, RawRepresentable, Equatable, Sendable {
        public typealias RawValue = String

        enum Backing: Equatable, Sendable {
            case rsa
            case ecdsa
            case octetKeyPair
            case unknown(String)

            var rawValue: String {
                switch self {
                case .rsa: "RSA"
                case .ecdsa: "EC"
                case .octetKeyPair: "OKP"
                case .unknown(let name): name
                }
            }

            init(rawValue: String) {
                switch rawValue {
                case "RSA": self = .rsa
                case "EC": self = .ecdsa
                case "OKP": self = .octetKeyPair
                default: self = .unknown(rawValue)
                }
            }
        }

        let backing: Backing

        public var rawValue: String {
            self.backing.rawValue
        }

        /// RSA
        public static let rsa = Self(backing: .rsa)
        /// ECDSA
        public static let ecdsa = Self(backing: .ecdsa)
        /// Octet Key Pair
        public static let octetKeyPair = Self(backing: .octetKeyPair)

        /// Represents a key type JWTKit doesn't recognise, preserving its name.
        public static func unknown(_ rawValue: String) -> Self { .init(backing: .unknown(rawValue)) }

        init(backing: Backing) {
            self.backing = backing
        }

        /// Creates a key type from its rawValue, falling back to `unknown` if it's not recognised.
        ///
        /// > Warning: This initialiser is failable due to source compatibility,
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
