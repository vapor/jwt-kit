import struct Foundation.Data
import class Foundation.JSONDecoder

 /// A JSON Web Key.
///
/// Read specification (RFC 7517) https://tools.ietf.org/html/rfc7517.
public struct JWK: Codable {
    
     /// The `use` (public key use) parameter identifies the intended use of the public key. The `use` parameter is employed to indicate whether a public key is used for encrypting data or verifying the signature on data.
    public var use: PublicKeyUse?

     /// Supported `kty` key types.
    public enum KeyType: String, Codable {
        /// RSA
        case rsa
        /// EC
        case ec
         
         /// Decodes from a lowercased string.
         public init(from decoder: Decoder) throws {
             let container = try decoder.singleValueContainer()
             let value = try container.decode(String.self).lowercased()
             switch value {
             case "rsa":
                 self = .rsa
             case "ec":
                self = .ec
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
     ///  family used with the key, such as `RSA` or `EC`. The `kty` value
     ///  is a case-sensitive string.
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

     /// The `x5u` (X.509 URL) parameter is a URI [RFC3986] that refers to a resource for an X.509 public key certificate or certificate chain [RFC5280].
    public var x5u: String?

     /// The `x5c` (X.509 certificate chain) parameter contains a chain of one or more PKIX certificates [RFC5280].
    public var x5c: [String]?

     /// The `x5t` (X.509 certificate SHA-1 thumbprint) parameter is a base64url-encoded SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].  Note that certificate thumbprints are also sometimes known as certificate fingerprints.
    public var x5t: String?

     /// The `x5t#S256` (X.509 certificate SHA-256 thumbprint) parameter is a base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate [RFC5280].
    public var x5tS256: String?

    // RSA keys
    // Represented as the base64url encoding of the value’s unsigned big endian representation as an octet sequence.
    /// `n` Modulus.
    public var modulus: String?

    /// `e` Exponent.
    public var exponent: String?

    /// `d` Private exponent.
    public var privateExponent: String?

    /// First prime factor.
    public var p: String?

    /// Second prime factor.
    public var q: String?

    /// First factor CRT exponent.
    public var dp: String?

    /// Second factor CRT exponent.
    public var dq: String?

    /// First CRT coefficient.
    public var qi: String?

    /// Other primes info.
    public var oth: OthType?

    // EC DSS keys
    public var crv: String?

    public var x: String?

    public var y: String?

    public enum OthType: String, Codable {
        case r
        case d
        case t
    }

    private enum CodingKeys: String, CodingKey {
        case keyType = "kty"
        case use
        case algorithm = "alg"
        case keyIdentifier = "kid"
        case x5u
        case x5c
        case x5t
        case x5tS256 = "x5t#S256"
        case modulus = "n"
        case exponent = "e"
        case privateExponent = "d"
        case p
        case q
        case dp
        case dq
        case qi
        case oth
        case crv
        case x
        case y
    }
    
    public init(json: String) throws {
        self = try JSONDecoder().decode(JWK.self, from: Data(json.utf8))
    }

    public init(
        kty: KeyType,
        use: PublicKeyUse? = nil,
        alg: Algorithm? = nil,
        kid: JWKIdentifier? = nil,
        x5u: String? = nil,
        x5c: [String]? = nil,
        x5t: String? = nil,
        x5tS256: String? = nil,
        n: String? = nil,
        e: String? = nil,
        d: String? = nil,
        p: String? = nil,
        q: String? = nil,
        dp: String? = nil,
        dq: String? = nil,
        qi: String? = nil,
        oth: OthType? = nil,
        crv: String? = nil,
        x: String? = nil,
        y: String? = nil
    ) {
        self.keyType = kty
        self.use = use
        self.algorithm = alg
        self.keyIdentifier = kid
        self.x5u = x5u
        self.x5c = x5c
        self.x5t = x5t
        self.x5tS256 = x5tS256
        self.modulus = n
        self.exponent = e
        self.privateExponent = d
        self.p = p
        self.q = q
        self.dp = dp
        self.dq = dq
        self.qi = qi
        self.oth = oth
        self.crv = crv
        self.x = x
        self.y = y
    }
}
