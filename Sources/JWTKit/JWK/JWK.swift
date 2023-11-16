import struct Foundation.Data
import class Foundation.JSONDecoder

/// A JSON Web Key.
///
/// Read specification (RFC 7517) https://tools.ietf.org/html/rfc7517.
public struct JWK: Codable, Sendable {
    public struct Curve: Codable, RawRepresentable, Sendable {
        public typealias RawValue = String
        
        let backing: Backing

        public var rawValue: String {
            backing.rawValue
        }

        public static let p256 = Self(backing: .p256)
        public static let p384 = Self(backing: .p384)
        public static let p521 = Self(backing: .p521)
        public static let ed25519 = Self(backing: .ed25519)
        public static let ed448 = Self(backing: .ed448)

        enum Backing: String, Codable {
            case p256 = "P-256"
            case p384 = "P-384"
            case p521 = "P-521"
            case ed25519 = "Ed25519"
            case ed448 = "Ed448"
        }

        init(backing: Backing) {
            self.backing = backing
        }

        public init?(rawValue: String) {
            guard let backing = Backing(rawValue: rawValue) else {
                return nil
            }
            self.init(backing: backing)
        }
        
        public init(from decoder: any Decoder) throws {
            self.init(backing: try decoder.singleValueContainer().decode(Backing.self))
        }
        
        public func encode(to encoder: any Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(self.backing)
        }
    }

    /// Supported `kty` key types.
    public struct KeyType: Codable, RawRepresentable, Equatable, Sendable {
        public typealias RawValue = String
        
        let backing: Backing

        public var rawValue: String {
            backing.rawValue
        }

        /// RSA
        public static let rsa = Self(backing: .rsa)
        /// ECDSA
        public static let ecdsa = Self(backing: .ecdsa)
        /// Octet Key Pair
        public static let octetKeyPair = Self(backing: .octetKeyPair)

        enum Backing: String, Codable {
            case rsa = "RSA"
            case ecdsa = "EC"
            case octetKeyPair = "OKP"
        }

        init(backing: Backing) {
            self.backing = backing
        }

        public init?(rawValue: String) {
            guard let backing = Backing(rawValue: rawValue) else {
                return nil
            }
            self.init(backing: backing)
        }
        
        public init(from decoder: any Decoder) throws {
            self.init(backing: try decoder.singleValueContainer().decode(Backing.self))
        }
        
        public func encode(to encoder: any Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(self.backing)
        }
    }

    /// The `kty` (key type) parameter identifies the cryptographic algorithm
    /// family used with the key, such as `RSA` or `ECDSA`. The `kty` value
    /// is a case-sensitive string.
    public var keyType: KeyType

    /// Supported `alg` algorithms
    public struct Algorithm: Codable, RawRepresentable, Equatable, Sendable {
        public typealias RawValue = String
        
        let backing: Backing

        public var rawValue: String {
            backing.rawValue
        }

        /// RSA with SHA256
        public static let rs256 = Self(backing: .rs256)
        /// RSA with SHA384
        public static let rs384 = Self(backing: .rs384)
        /// RSA with SHA512
        public static let rs512 = Self(backing: .rs512)
        /// EC with SHA256
        public static let es256 = Self(backing: .es256)
        /// EC with SHA384
        public static let es384 = Self(backing: .es384)
        /// EC with SHA512
        public static let es512 = Self(backing: .es512)
        /// EdDSA
        public static let eddsa = Self(backing: .eddsa)

        enum Backing: String, Codable {
            case rs256 = "RS256"
            case rs384 = "RS384"
            case rs512 = "RS512"
            case es256 = "ES256"
            case es384 = "ES384"
            case es512 = "ES512"
            case eddsa = "EdDSA"
        }

        init(backing: Backing) {
            self.backing = backing
        }

        public init?(rawValue: String) {
            guard let backing = Backing(rawValue: rawValue) else {
                return nil
            }
            self.init(backing: backing)
        }
        
        public init(from decoder: any Decoder) throws {
            self.init(backing: try decoder.singleValueContainer().decode(Backing.self))
        }
        
        public func encode(to encoder: any Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(self.backing)
        }
    }

    /// The `alg` (algorithm) parameter identifies the algorithm intended for
    /// use with the key. The `alg` value is a case-sensitive ASCII string.
    public var algorithm: Algorithm?

    /// The `kid` (key ID) parameter is used to match a specific key. This is
    /// used, for instance, to choose among a set of keys within a JWK Set
    /// during key rollover.
    ///
    /// The structure of the `kid` value is unspecified. When `kid` values
    /// are used within a JWK Set, different keys within the JWK set should
    /// use distinct `kid` values.
    ///
    /// (One example in which different keys might use the same `kid` value
    /// is if they have different `kty` (key type) values but are considered to be
    /// equivalent alternatives by the application using them.)
    ///
    /// The `kid` value is a case-sensitive string.
    public var keyIdentifier: JWKIdentifier?

    // RSA keys
    // Represented as the base64url encoding of the value’s unsigned big endian representation as an octet sequence.
    /// `n` Modulus.
    public var modulus: String?

    /// `e` Exponent.
    public var exponent: String?

    /// `d` Private exponent.
    public var privateExponent: String?

    // ECDSA keys
    public var x: String?

    public var y: String?

    public var curve: Curve?

    private enum CodingKeys: String, CodingKey {
        case keyType = "kty"
        case algorithm = "alg"
        case keyIdentifier = "kid"
        case modulus = "n"
        case exponent = "e"
        case privateExponent = "d"
        case curve = "crv"
        case x
        case y
    }

    public init(json: String) throws {
        self = try JSONDecoder().decode(JWK.self, from: Data(json.utf8))
    }

    public static func rsa(_ algorithm: Algorithm?, identifier: JWKIdentifier?, modulus: String?, exponent: String?, privateExponent: String? = nil) -> JWK {
        JWK(keyType: .rsa, algorithm: algorithm, keyIdentifier: identifier, modulus: modulus, exponent: exponent, privateExponent: privateExponent)
    }

    public static func ecdsa(_ algorithm: Algorithm?, identifier: JWKIdentifier?, x: String?, y: String?, curve: ECDSACurve?, privateKey: String? = nil) -> JWK {
        JWK(keyType: .ecdsa, algorithm: algorithm, keyIdentifier: identifier, privateExponent: privateKey, x: x, y: y, curve: curve.flatMap { Curve(rawValue: $0.description) })
    }

    public static func octetKeyPair(_ algorithm: Algorithm?, identifier: JWKIdentifier?, x: String?, y _: String?, curve: EdDSAKey.Curve?, privateKey: String? = nil) -> JWK {
        JWK(keyType: .octetKeyPair, algorithm: algorithm, keyIdentifier: identifier, privateExponent: privateKey, x: x, curve: curve.flatMap { Curve(rawValue: $0.rawValue) })
    }

    private init(
        keyType: KeyType,
        algorithm: Algorithm? = nil,
        keyIdentifier: JWKIdentifier? = nil,
        modulus: String? = nil,
        exponent: String? = nil,
        privateExponent: String? = nil,
        x: String? = nil,
        y: String? = nil,
        curve: Curve? = nil
    ) {
        self.keyType = keyType
        self.algorithm = algorithm
        self.keyIdentifier = keyIdentifier
        self.modulus = modulus
        self.exponent = exponent
        self.privateExponent = privateExponent
        self.x = x
        self.y = y
        self.curve = curve
    }
}
