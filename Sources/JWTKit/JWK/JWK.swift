import struct Foundation.Data
import class Foundation.JSONDecoder

/// A JSON Web Key.
///
/// Read specification (RFC 7517) https://tools.ietf.org/html/rfc7517.
public struct JWK: Codable {
    /// Supported `kty` key types.
    public enum KeyType: String, Codable {
        /// RSA
        case rsa
        /// ECDSA
        case ecdsa
         
        /// Decodes from a lowercased string.
        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            let value = try container.decode(String.self).lowercased()
            switch value {
            case "rsa":
                self = .rsa
            case "ecdsa":
                self = .ecdsa
            default:
                throw JWTError.invalidJWK
            }
        }
        
        /// Encodes to a lowercased string.
        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(self.rawValue)
        }
    }
     
    /// The `kty` (key type) parameter identifies the cryptographic algorithm
    /// family used with the key, such as `RSA` or `ECDSA`. The `kty` value
    /// is a case-sensitive string.
    public var keyType: KeyType
     
    /// Supported `alg` algorithms
    public enum Algorithm: String, Codable {
        /// RSA with SHA256
        case rs256
        /// RSA with SHA384
        case rs384
        /// RSA with SHA512
        case rs512
        /// EC with SHA256
        case es256
        /// EC with SHA384
        case es384
        /// EC with SHA512
        case es512

        init?(string: String) {
            switch string.lowercased() {
            case "rs256":
                self = .rs256
            case "rs384":
                self = .rs384
            case "rs512":
                self = .rs512
            case "es256":
                self = .es256
            case "es384":
                self = .es384
            case "es512":
                self = .es512
            default:
                return nil
            }
        }
         
        /// Decodes from a lowercased string.
        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            let string = try container.decode(String.self)
            guard let algorithm = Self(string: string) else {
                throw JWTError.invalidJWK
            }
            self = algorithm
        }
        
        /// Encodes to a lowercased string.
        public func encode(to encoder: Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(self.rawValue)
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

    private enum CodingKeys: String, CodingKey {
        case keyType = "kty"
        case algorithm = "alg"
        case keyIdentifier = "kid"
        case modulus = "n"
        case exponent = "e"
        case privateExponent = "d"
        case x
        case y
    }

    public init(json: String) throws {
        self = try JSONDecoder().decode(JWK.self, from: Data(json.utf8))
    }
    
    public static func rsa(_ algorithm: Algorithm, identifier: JWKIdentifier, modulus: String, exponent: String, privateExponent: String) -> JWK {
        JWK(keyType: .rsa, algorithm: algorithm, keyIdentifier: identifier, n: modulus, e: exponent, d: privateExponent, x: nil, y: nil)
    }
    
    public static func ecdsa(_ algorithm: Algorithm, identifier: JWKIdentifier, x: String, y: String) -> JWK {
        return JWK(keyType: .ecdsa, algorithm: algorithm, keyIdentifier: identifier, n: nil, e: nil, d: nil, x: x, y: y)
    }
    
    private init(
        keyType: KeyType,
        algorithm: Algorithm? = nil,
        keyIdentifier: JWKIdentifier? = nil,
        n: String? = nil,
        e: String? = nil,
        d: String? = nil,
        x: String? = nil,
        y: String? = nil
    ) {
        self.keyType = keyType
        self.algorithm = algorithm
        self.keyIdentifier = keyIdentifier
        self.modulus = n
        self.exponent = e
        self.privateExponent = d
        self.x = x
        self.y = y
    }
}
