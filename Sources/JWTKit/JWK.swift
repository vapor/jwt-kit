/// A JSON Web Key Set.
///
/// A JSON object that represents a set of JWKs.
/// Read specification (RFC 7517) https://tools.ietf.org/html/rfc7517.
public struct JWKS: Decodable {
    /// All JSON Web Keys
    public var keys: [JWK]

    /// Retrieves the desired key from the JSON Web Key Set
    /// - Parameters:
    ///   - keyIdentifier: The `kid` value to lookup.
    ///   - keyType: The `kty` value.
    public func find(keyIdentifier: String, keyType: JWK.KeyType) -> JWK? {
        keys.filter { $0.keyType == keyType && $0.keyIdentifier?.string == keyIdentifier }.first
    }

    /// Retrieves the desired key from the JSON Web Key Set
    /// - Parameters:
    ///   - keyIdentifier: The `kid` value to lookup.
    ///   - keyType: The `kty` value.
    public func find(keyIdentifier: JWKIdentifier, keyType: JWK.KeyType) -> JWK? {
        find(keyIdentifier: keyIdentifier.string, keyType: keyType)
    }

    /// Retrieves the desired keys from the JSON Web Key Set
    /// Multiple keys can have the same `kid` if they have different `kty` values.
    /// - Parameter keyIdentifier: The `kid` value to lookup.
    public func find(keyIdentifier: String) -> [JWK]? {
        keys.filter { $0.keyIdentifier?.string == keyIdentifier }
    }

    /// Retrieves the desired keys from the JSON Web Key Set
    /// Multiple keys can have the same `kid` if they have different `kty` values.
    /// - Parameter keyIdentifier: The `kid` value to lookup.
    public func find(keyIdentifier: JWKIdentifier) -> [JWK]? {
        find(keyIdentifier: keyIdentifier.string)
    }
}

public struct JWKIdentifier: Hashable, Equatable {
    public let string: String

    public init(string: String) {
        self.string = string
    }
}

extension JWKIdentifier: Codable {
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()
        try self.init(string: container.decode(String.self))
    }

    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        try container.encode(self.string)
    }
}

extension JWKIdentifier: ExpressibleByStringLiteral {
    public init(stringLiteral value: String) {
        self.init(string: value)
    }
}

/// A JSON Web Key.
///
/// Read specification (RFC 7517) https://tools.ietf.org/html/rfc7517.
public struct JWK: Decodable {
    /// Supported `kty` key types.
    public enum KeyType: Decodable {
        /// RSA
        case rsa
        
        /// Decodes from a lowercased string.
        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            let value = try container.decode(String.self).lowercased()
            switch value {
            case "rsa":
                self = .rsa
            default:
                throw JWTError.invalidJWK
            }
        }
    }
    
    /// The `kty` (key type) parameter identifies the cryptographic algorithm
    ///  family used with the key, such as `RSA` or `EC`. The `kty` value
    ///  is a case-sensitive string.
    public var keyType: KeyType
    
    /// Supported `alg` algorithms
    public enum Algorithm: Decodable {
        /// RSA with SHA256
        case rs256
        /// RSA with SHA384
        case rs384
        /// RSA with SHA512
        case rs512
        
        /// Decodes from a lowercased string.
        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            let value = try container.decode(String.self).lowercased()
            switch value {
            case "rs256":
                self = .rs256
            case "rs384":
                self = .rs384
            case "rs512":
                self = .rs512
            default:
                throw JWTError.invalidJWK
            }
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
    
    /// `n` Modulus.
    public var modulus: String?
    
    /// `e` Exponent.
    public var exponent: String?
    
    /// `d` Private exponent.
    public var privateExponent: String?
    
    private enum CodingKeys: String, CodingKey {
        case keyType = "kty"
        case algorithm = "alg"
        case keyIdentifier = "kid"
        case modulus = "n"
        case exponent = "e"
        case privateExponent = "d"
    }
}
