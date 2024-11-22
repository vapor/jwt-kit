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

    private init(
        keyType: KeyType,
        algorithm: Algorithm? = nil,
        keyIdentifier: JWKIdentifier? = nil,
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
    /// Supported `alg` algorithms
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
        public static func ecdsa(_ curve: ECDSACurve) -> Self { .init(.ecdsa(curve)) }

        /// Represents an EdDSA curve.
        public static func eddsa(_ curve: EdDSACurve) -> Self { .init(.eddsa(curve)) }

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
    
