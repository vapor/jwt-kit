import Foundation
@_implementationOnly import CJWTKitBoringSSL
import Crypto

public final class ECDSAKey: OpenSSLKey {
    
    public enum Curve: String, Codable {
        case p256 = "P-256"
        case p384 = "P-384"
        case p521 = "P-521"
        case ed25519 = "Ed25519"
        case ed448 = "Ed448"
    }
    
    @available(*, deprecated, message: "Unavailable in v5. Please use ES256PrivateKey(), ES384PrivateKey(), or ES512PrivateKey() instead.")
    public static func generate(curve: Curve = .p521) throws -> ECDSAKey {
        guard let c = CJWTKitBoringSSL_EC_KEY_new_by_curve_name(curve.cName) else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.newKeyByCurveFailure)
        }
        guard CJWTKitBoringSSL_EC_KEY_generate_key(c) != 0 else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.generateKeyFailure)
        }
        return .init(c)
    }
    
    /// Creates ECDSAKey from public certificate pem file.
    ///
    /// Certificate pem files look like:
    ///
    ///     -----BEGIN CERTIFICATE-----
    ///     MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
    ///     ...
    ///     -----END CERTIFICATE-----
    ///
    /// This key can only be used to verify JWTs.
    ///
    /// - parameters:
    ///     - pem: Contents of pem file.
    @available(*, deprecated, message: "Unavailable in v5. Please use ES256PublicKey(certificate:), ES384PublicKey(certificate:), or ES512PublicKey(certificate:) instead. Note that more interfaces for importing keys is available once you update fully to v5.")
    public static func certificate(pem string: String) throws -> ECDSAKey {
        try self.certificate(pem: [UInt8](string.utf8))
    }

    /// Creates ECDSAKey from public certificate pem file.
    ///
    /// Certificate pem files look like:
    ///
    ///     -----BEGIN CERTIFICATE-----
    ///     MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC0cOtPjzABybjzm3fCg1aCYwnx
    ///     ...
    ///     aX4rbSL49Z3dAQn8vQIDAQAB
    ///     -----END CERTIFICATE-----
    ///
    /// This key can only be used to verify JWTs.
    ///
    /// - parameters:
    ///     - pem: Contents of pem file.
    @available(*, deprecated, message: "Unavailable in v5. Please use ES256PublicKey(certificate:), ES384PublicKey(certificate:), or ES512PublicKey(certificate:) instead. Note that more interfaces for importing keys is available once you update fully to v5.")
    public static func certificate<Data>(pem data: Data) throws -> ECDSAKey
        where Data: DataProtocol
    {
        let x509 = try self.load(pem: data) { bio in
            CJWTKitBoringSSL_PEM_read_bio_X509(bio, nil, nil, nil)
        }
        defer { CJWTKitBoringSSL_X509_free(x509) }
        let pkey = CJWTKitBoringSSL_X509_get_pubkey(x509)
        defer { CJWTKitBoringSSL_EVP_PKEY_free(pkey) }

        guard let c = CJWTKitBoringSSL_EVP_PKEY_get1_EC_KEY(pkey) else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.newKeyByCurveFailure)
        }
        return self.init(c)
    }
    
    @available(*, deprecated, message: "Unavailable in v5. Please use ES256PublicKey(pem:), ES384PublicKey(pem:), or ES512PublicKey(pem:) instead. Note that more interfaces for importing keys is available once you update fully to v5.")
    public static func `public`(pem string: String) throws -> ECDSAKey {
        try .public(pem: [UInt8](string.utf8))
    }

    @available(*, deprecated, message: "Unavailable in v5. Please use ES256PublicKey(pem:), ES384PublicKey(pem:), or ES512PublicKey(pem:) instead. Note that more interfaces for importing keys is available once you update fully to v5.")
    public static func `public`<Data>(pem data: Data) throws -> ECDSAKey
        where Data: DataProtocol
    {
        let c = try self.load(pem: data) { bio in
            CJWTKitBoringSSL_PEM_read_bio_EC_PUBKEY(bio, nil, nil, nil)
        }
        return self.init(c)
    }

    @available(*, deprecated, message: "Unavailable in v5. Please use ES256PrivateKey(pem:), ES384PrivateKey(pem:), or ES512PrivateKey(pem:) instead. Note that more interfaces for importing keys is available once you update fully to v5.")
    public static func `private`(pem string: String) throws -> ECDSAKey {
        try .private(pem: [UInt8](string.utf8))
    }

    @available(*, deprecated, message: "Unavailable in v5. Please use ES256PrivateKey(pem:), ES384PrivateKey(pem:), or ES512PrivateKey(pem:) instead. Note that more interfaces for importing keys is available once you update fully to v5.")
    public static func `private`<Data>(pem data: Data) throws -> ECDSAKey
        where Data: DataProtocol
    {
        let c = try self.load(pem: data) { bio in
            CJWTKitBoringSSL_PEM_read_bio_ECPrivateKey(bio, nil, nil, nil)
        }
        return self.init(c)
    }

    let c: OpaquePointer

    init(_ c: OpaquePointer) {
        self.c = c
    }
    
    @available(*, deprecated, message: "Unavailable in v5. Please use ES256PublicKey(parameters:), ES384PublicKey(parameters:), or ES512PublicKey(parameters:) instead. Note that more interfaces for importing private keys is available once you update fully to v5.")
    public convenience init(parameters: Parameters, curve: Curve = .p521, privateKey: String? = nil) throws {
        guard let c = CJWTKitBoringSSL_EC_KEY_new_by_curve_name(curve.cName) else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.newKeyByCurveFailure)
        }
        
        guard let bnX = BigNumber(base64URL: parameters.x) else {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "Unable to interpret x as BN")
        }
        guard let bnY = BigNumber(base64URL: parameters.y) else {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "Unable to interpret y as BN")
        }

        if CJWTKitBoringSSL_EC_KEY_set_public_key_affine_coordinates(c, bnX.c, bnY.c) != 1 {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "Unable to set public key")
        }
        
        if let privateKey = privateKey {
            guard let bnPrivate = BigNumber(base64URL: privateKey) else {
                throw JWTError.generic(identifier: "ecPrivateKey", reason: "Unable to interpret privateKey as BN")
            }
            if CJWTKitBoringSSL_EC_KEY_set_private_key(c, bnPrivate.c) != 1 {
                throw JWTError.generic(identifier: "ecPrivateKey", reason: "Unable to set private key")
            }
        }

        self.init(c)
    }

    deinit {
        CJWTKitBoringSSL_EC_KEY_free(self.c)
    }
  
    public var curve: Curve? {
        let group: OpaquePointer = CJWTKitBoringSSL_EC_KEY_get0_group(self.c)
        let cName = CJWTKitBoringSSL_EC_GROUP_get_curve_name(group)
        return Curve(cName: cName)
    }
    
    public var parameters: Parameters? {
        let group: OpaquePointer = CJWTKitBoringSSL_EC_KEY_get0_group(self.c)
        let pubKey: OpaquePointer = CJWTKitBoringSSL_EC_KEY_get0_public_key(self.c)

        let bnX = BigNumber()
        let bnY = BigNumber()
        if (CJWTKitBoringSSL_EC_POINT_get_affine_coordinates_GFp(group, pubKey, bnX.c, bnY.c, nil) != 1) {
            return nil
        }

        return Parameters(x: bnX.toBase64URL(), y: bnY.toBase64URL())
    }

    public struct Parameters {
        public let x: String
        public let y: String
    }
}

extension ECDSAKey.Curve {
    var cName: Int32 {
        switch self {
        case .p256:
            return NID_X9_62_prime256v1
        case .p384:
            return NID_secp384r1
        case .p521:
            return NID_secp521r1
        case .ed25519:
            return NID_ED25519
        case .ed448:
            return NID_ED448
        }
    }
  
    init?(cName: Int32) {
        switch cName {
        case NID_X9_62_prime256v1:
            self = .p256
        case NID_secp384r1:
            self = .p384
        case NID_secp521r1:
            self = .p521
        case NID_ED25519:
            self = .ed25519
        case NID_ED448:
            self = .ed448
        default:
            return nil
        }
    }
}

#if compiler(>=6)
public protocol ECDSACurveType: Sendable {
    static var curve: ECDSAKey.Curve { get }
}

extension P256: ECDSACurveType, @unchecked @retroactive Sendable {
    static public var curve: ECDSAKey.Curve { .p256 }
}

extension P384: ECDSACurveType, @unchecked @retroactive Sendable {
    static public var curve: ECDSAKey.Curve { .p384 }
}

extension P521: ECDSACurveType, @unchecked @retroactive Sendable {
    static public var curve: ECDSAKey.Curve { .p521 }
}
#else
public protocol ECDSACurveType {
    static var curve: ECDSAKey.Curve { get }
}

extension P256: ECDSACurveType {
    static public var curve: ECDSAKey.Curve { .p256 }
}

extension P384: ECDSACurveType {
    static public var curve: ECDSAKey.Curve { .p384 }
}

extension P521: ECDSACurveType {
    static public var curve: ECDSAKey.Curve { .p521 }
}
#endif

public typealias ES256PublicKey = ECDSA.PublicKey<P256>
public typealias ES256PrivateKey = ECDSA.PrivateKey<P256>

public typealias ES384PublicKey = ECDSA.PublicKey<P384>
public typealias ES384PrivateKey = ECDSA.PrivateKey<P384>

public typealias ES512PublicKey = ECDSA.PublicKey<P521>
public typealias ES512PrivateKey = ECDSA.PrivateKey<P521>

public enum ECDSA {
    /// ECDSA.PublicKey was introduced in v5 and replaces ``ECDSAKey``.
    ///
    /// - Note: Please migrate over to ``ECDSA/PublicKey`` before updating to v5, though if you plan on remaining on v4, ``ECDSAKey`` can continue to be used.
    public struct PublicKey<Curve: ECDSACurveType> {
        let key: ECDSAKey
        init(key: ECDSAKey) { self.key = key }
        
        public var curve: ECDSAKey.Curve? { key.curve }
        public var parameters: ECDSAKey.Parameters? { key.parameters }

        /// Creates an ``ECDSA.PublicKey`` instance from a PEM encoded certificate string.
        ///
        /// - Parameter pem: The PEM encoded certificate string.
        /// - Throws: If there is a problem parsing the certificate or deriving the public key.
        /// - Returns: A new ``ECDSAKey`` instance with the public key from the certificate.
        public init(certificate pem: String) throws {
            key = try ECDSAKey.certificate(pem: pem)
        }

        /// Creates an ``ECDSA.PublicKey`` instance from a PEM encoded certificate data.
        ///
        /// - Parameter pem: The PEM encoded certificate data.
        /// - Throws: If there is a problem parsing the certificate or deriving the public key.
        /// - Returns: A new ``ECDSA.PublicKey`` instance with the public key from the certificate.
        public init<Data: DataProtocol>(certificate pem: Data) throws {
            key = try ECDSAKey.certificate(pem: pem)
        }

        /// Creates an ``ECDSA.PublicKey`` instance from a PEM encoded public key string.
        ///
        /// - Parameter pem: The PEM encoded public key string.
        /// - Throws: If there is a problem parsing the public key.
        /// - Returns: A new ``ECDSA.PublicKey`` instance with the public key from the certificate.
        public init(pem string: String) throws {
            key = try ECDSAKey.public(pem: string)
        }

        /// Creates an ``ECDSA.PublicKey`` instance from a PEM encoded public key data.
        ///
        /// - Parameter pem: The PEM encoded public key data.
        /// - Throws: If there is a problem parsing the public key.
        /// - Returns: A new ``ECDSA.PublicKey`` instance with the public key from the certificate.
        public init<Data: DataProtocol>(pem data: Data) throws {
            key = try ECDSAKey.public(pem: data)
        }

        /// Initializes a new ``ECDSA.PublicKey` with ECDSA parameters.
        ///
        /// - Parameters:
        ///   - parameters: The ``ECDSAParameters`` tuple containing the x and y coordinates of the public key. These coordinates should be base64 URL encoded strings.
        ///
        /// - Throws:
        ///   - ``JWTError/generic`` with the identifier `ecCoordinates` if the x and y coordinates from `parameters` cannot be interpreted as base64 encoded data.
        ///   - ``JWTError/generic`` with the identifier `ecPrivateKey` if the provided `privateKey` is non-nil but cannot be interpreted as a valid `PrivateKey`.
        ///
        /// - Note:
        ///   The ``ECDSAParameters`` tuple is assumed to have x and y properties that are base64 URL encoded strings representing the respective coordinates of an ECDSA public key.
        public init(parameters: ECDSAKey.Parameters) throws {
            key = try ECDSAKey(parameters: parameters, curve: Curve.curve, privateKey: nil)
        }
    }

    /// ECDSA.PrivateKey was introduced in v5 and replaces ``ECDSAKey``.
    ///
    /// - Note: Please migrate over to ``ECDSA/PrivateKey`` before updating to v5, though if you plan on remaining on v4, ``ECDSAKey`` can continue to be used.
    public struct PrivateKey<Curve: ECDSACurveType> {
        let key: ECDSAKey
        init(key: ECDSAKey) { self.key = key }
        
        public var curve: ECDSAKey.Curve? { key.curve }
        public var parameters: ECDSAKey.Parameters? { key.parameters }

        /// Creates an ``ECDSA.PrivateKey`` instance from a PEM encoded private key string.
        ///
        /// - Parameter pem: The PEM encoded private key string.
        /// - Throws: If there is a problem parsing the private key.
        /// - Returns: A new ``ECDSA.PrivateKey`` instance with the private key.
        public init(pem string: String) throws {
            key = try ECDSAKey.public(pem: string)
        }

        /// Creates an ``ECDSA.PrivateKey`` instance from a PEM encoded private key data.
        ///
        /// - Parameter pem: The PEM encoded private key data.
        /// - Throws: If there is a problem parsing the private key.
        /// - Returns: A new ``ECDSA.PrivateKey`` instance with the private key.
        public init<Data: DataProtocol>(pem data: Data) throws {
            key = try ECDSAKey.public(pem: data)
        }

        /// Generates a new ECDSA key.
        ///
        /// - Returns: A new ``ECDSA.PrivateKey`` instance with the generated key.
        public init() {
            key = try! ECDSAKey.generate(curve: Curve.curve)
        }
    }
}

extension ECDSA.PublicKey<P256> {
    public init(backing: Curve.Signing.PublicKey) throws {
        let representation = backing.rawRepresentation
        try self.init(parameters: ECDSAKey.Parameters(
            x: representation.prefix(representation.count/2).base64URLEncodedString(),
            y: representation.suffix(representation.count/2).base64URLEncodedString()
        ))
    }
}

extension ECDSA.PublicKey<P384> {
    public init(backing: Curve.Signing.PublicKey) throws {
        let representation = backing.rawRepresentation
        try self.init(parameters: ECDSAKey.Parameters(
            x: representation.prefix(representation.count/2).base64URLEncodedString(),
            y: representation.suffix(representation.count/2).base64URLEncodedString()
        ))
    }
}

extension ECDSA.PublicKey where Curve == P521 {
    public init(backing: Curve.Signing.PublicKey) throws {
        let representation = backing.rawRepresentation
        try self.init(parameters: ECDSAKey.Parameters(
            x: representation.prefix(representation.count/2).base64URLEncodedString(),
            y: representation.suffix(representation.count/2).base64URLEncodedString()
        ))
    }
}

extension ECDSA.PrivateKey<P256> {
    public init(backing: Curve.Signing.PrivateKey) throws {
        let representation = backing.publicKey.rawRepresentation
        try self.init(key: ECDSAKey(
            parameters: ECDSAKey.Parameters(
                x: representation.prefix(representation.count/2).base64URLEncodedString(),
                y: representation.suffix(representation.count/2).base64URLEncodedString()
            ),
            curve: Curve.curve,
            privateKey: backing.rawRepresentation.base64URLEncodedString()
        ))
    }
}

extension ECDSA.PrivateKey<P384> {
    public init(backing: Curve.Signing.PrivateKey) throws {
        let representation = backing.publicKey.rawRepresentation
        try self.init(key: ECDSAKey(
            parameters: ECDSAKey.Parameters(
                x: representation.prefix(representation.count/2).base64URLEncodedString(),
                y: representation.suffix(representation.count/2).base64URLEncodedString()
            ),
            curve: Curve.curve,
            privateKey: backing.rawRepresentation.base64URLEncodedString()
        ))
    }
}

extension ECDSA.PrivateKey<P521> {
    public init(backing: Curve.Signing.PrivateKey) throws {
        let representation = backing.publicKey.rawRepresentation
        try self.init(key: ECDSAKey(
            parameters: ECDSAKey.Parameters(
                x: representation.prefix(representation.count/2).base64URLEncodedString(),
                y: representation.suffix(representation.count/2).base64URLEncodedString()
            ),
            curve: Curve.curve,
            privateKey: backing.rawRepresentation.base64URLEncodedString()
        ))
    }
}
