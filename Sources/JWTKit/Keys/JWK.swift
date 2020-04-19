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
    public enum Algorithm: String, Decodable {
        /// RSA with SHA256
        case rs256 = "RS256"
        /// RSA with SHA384
        case rs384 = "RS384"
        /// RSA with SHA512
        case rs512 = "RS512"
        
        /// Decodes from a lowercased string.
        public init(from decoder: Decoder) throws {
            let container = try decoder.singleValueContainer()
            let value = try container.decode(String.self).uppercased()
            
            guard let algorithm = Algorithm.init(rawValue: value) else {
                throw JWTError.invalidJWK
            }
            
            self = algorithm
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
