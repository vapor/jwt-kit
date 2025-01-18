import struct Foundation.Data
import class Foundation.JSONDecoder

/// A JSON Web Key, according to RFC 7517.
/// See: https://tools.ietf.org/html/rfc7517.
public struct JWK: Codable, Sendable {
    // MARK: Properties

    /// The `kty` (key type) parameter identifies the cryptographic algorithm
    /// family used with the key, such as `RSA` or `ECDSA`.
    public var keyType: KeyType

    /// The `alg` (algorithm) parameter identifies the algorithm intended for
    /// use with the key.
    public var algorithm: Algorithm?

    /// The `kid` (key ID) parameter is used to identify a specific key,
    /// often in a set of keys.
    public var keyIdentifier: JWKIdentifier?
    
    /// The `use` parameter identifies the intended use of the key.
    public var use: Usage?
    
    /// The `key_ops` (key operations) parameter identifies the operation(s)
    /// for which the key is intended to be used.
    public var keyOperations: [KeyOperation]?
    
    /// The `x5u` (X.509 URL) parameter is a URI that refers to a resource
    /// for an X.509 public key certificate or certificate chain.
    public var x509URL: String?
    
    /// The `x5c` (X.509 certificate chain) parameter contains a chain of one
    /// or more PKIX certificates.
    public var x509CertificateChain: [String]?
    
    /// The `x5t` (X.509 certificate SHA-1 thumbprint) parameter is a base64url-encoded
    /// SHA-1 thumbprint (a.k.a. digest) of the DER encoding of an X.509 certificate.
    public var x509CertificateSHA1Thumbprint: String?
    
    /// The `x5t#S256` (X.509 certificate SHA-256 thumbprint) parameter is a
    /// base64url-encoded SHA-256 thumbprint (a.k.a. digest) of the DER encoding
    /// of an X.509 certificate.
    public var x509CertificateSHA256Thumbprint: String?
    
    // MARK: RSA keys

    // RSA modulus as a Base64 URL encoded string.
    public var modulus: String?

    /// RSA public exponent as a Base64 URL encoded string.
    public var exponent: String?

    /// RSA private exponent as a Base64 URL encoded string.
    public var privateExponent: String?

    /// RSA first prime factor as a Base64 URL encoded string.
    public var prime1: String?

    /// RSA second prime factor as a Base64 URL encoded string.
    public var prime2: String?

    // MARK: ECDSA keys

    /// ECDSA x-coordinate as a Base64 URL encoded string.
    public var x: String?

    /// ECDSA y-coordinate as a Base64 URL encoded string.
    public var y: String?

    /// `crv` (curve) parameter identifying the cryptographic curve used.
    public var curve: Curve?

    private enum CodingKeys: String, CodingKey {
        case keyType = "kty"
        case algorithm = "alg"
        case keyIdentifier = "kid"
        case modulus = "n"
        case exponent = "e"
        case privateExponent = "d"
        case prime1 = "p"
        case prime2 = "q"
        case curve = "crv"
        case x
        case y
        case use = "use"
        case keyOperations = "key_ops"
        case x509URL = "x5u"
        case x509CertificateChain = "x5c"
        case x509CertificateSHA1Thumbprint = "x5t"
        case x509CertificateSHA256Thumbprint = "x5t#S256"
    }

    public static func rsa(
        _ algorithm: Algorithm?,
        identifier: JWKIdentifier?,
        modulus: String?,
        exponent: String?,
        privateExponent: String? = nil
    ) -> JWK {
        .init(
            keyType: .rsa,
            algorithm: algorithm,
            keyIdentifier: identifier,
            modulus: modulus,
            exponent: exponent,
            privateExponent: privateExponent
        )
    }

    public static func ecdsa(
        _ algorithm: Algorithm?,
        identifier: JWKIdentifier?,
        x: String?,
        y: String?,
        curve: ECDSACurve?,
        privateKey: String? = nil
    ) -> JWK {
        .init(
            keyType: .ecdsa,
            algorithm: algorithm,
            keyIdentifier: identifier,
            privateExponent: privateKey,
            x: x,
            y: y,
            curve: curve.flatMap { Curve(rawValue: $0.rawValue) }
        )
    }

    public static func octetKeyPair(
        _ algorithm: Algorithm?,
        identifier: JWKIdentifier?,
        x: String?,
        y _: String?,
        curve: EdDSACurve?,
        privateKey: String? = nil
    ) -> JWK {
        .init(
            keyType: .octetKeyPair,
            algorithm: algorithm,
            keyIdentifier: identifier,
            privateExponent: privateKey,
            x: x,
            curve: curve.flatMap { Curve(rawValue: $0.rawValue) }
        )
    }

    public init(json: String) throws {
        self = try JSONDecoder().decode(JWK.self, from: Data(json.utf8))
    }

    init(
        keyType: KeyType,
        algorithm: Algorithm? = nil,
        keyIdentifier: JWKIdentifier? = nil,
        use: JWK.Usage? = nil,
        keyOperations: [JWK.KeyOperation]? = nil,
        x509URL: String? = nil,
        x509CertificateChain: [String]? = nil,
        x509CertificateSHA1Thumbprint: String? = nil,
        x509CertificateSHA256Thumbprint: String? = nil,
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
        self.algorithm = algorithm
        self.keyIdentifier = keyIdentifier
        self.use = use
        self.keyOperations = keyOperations
        self.x509URL = x509URL
        self.x509CertificateChain = x509CertificateChain
        self.x509CertificateSHA1Thumbprint = x509CertificateSHA1Thumbprint
        self.x509CertificateSHA256Thumbprint = x509CertificateSHA256Thumbprint
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

extension JWK {
    public struct Curve: Codable, RawRepresentable, Equatable, Sendable {
        enum Backing: Codable {
            case ecdsa(ECDSACurve)
            case eddsa(EdDSACurve)
        }

        let backing: Backing

        public var rawValue: String {
            switch self.backing {
            case .ecdsa(let ecdsaCurve): ecdsaCurve.rawValue
            case .eddsa(let eddsaCurve): eddsaCurve.rawValue
            }
        }

        /// Represents an ECDSA curve.
        public static func ecdsa(_ curve: ECDSACurve) -> Self { .init(.ecdsa(curve))
        }

        /// Represents an EdDSA curve.
        public static func eddsa(_ curve: EdDSACurve) -> Self { .init(.eddsa(curve))
        }

        init(_ backing: Backing) {
            self.backing = backing
        }

        public init?(rawValue: String) {
            if let ecdsaCurve = ECDSACurve(rawValue: rawValue) {
                self.init(.ecdsa(ecdsaCurve))
            } else if let eddsaCurve = EdDSACurve(rawValue: rawValue) {
                self.init(.eddsa(eddsaCurve))
            } else {
                return nil
            }
        }

        public init(from decoder: any Decoder) throws {
            let container = try decoder.singleValueContainer()
            if let ecdsaCurve = try? container.decode(ECDSACurve.self) {
                self = .ecdsa(ecdsaCurve)
            } else if let eddsaCurve = try? container.decode(EdDSACurve.self) {
                self = .eddsa(eddsaCurve)
            } else {
                throw DecodingError.dataCorruptedError(in: container, debugDescription: "Curve type not supported")
            }
        }

        public func encode(to encoder: any Encoder) throws {
            switch self.backing {
            case .ecdsa(let ecdsaCurve):
                try ecdsaCurve.encode(to: encoder)
            case .eddsa(let eddsaCurve):
                try eddsaCurve.encode(to: encoder)
            }
        }
    }
}
