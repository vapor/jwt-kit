@_implementationOnly import CJWTKitBoringSSL

public final class ECDSAKey: OpenSSLKey {
    public enum Curve: String, Codable {
        case p256 = "P-256"
        case p384 = "P-384"
        case p521 = "P-521"

        var cName: Int32 {
            switch self {
            case .p256:
                return NID_X9_62_prime256v1
            case .p384:
                return NID_secp384r1
            case .p521:
                return NID_secp521r1
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
            default:
                return nil
            }
        }
    }
    
    public static func generate(curve: Curve = .p521) throws -> ECDSAKey {
        guard let c = CJWTKitBoringSSL_EC_KEY_new_by_curve_name(curve.cName) else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.newKeyByCurveFailure)
        }
        guard CJWTKitBoringSSL_EC_KEY_generate_key(c) != 0 else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.generateKeyFailure)
        }
        return .init(c)
    }
    
    public static func `public`(pem string: String) throws -> ECDSAKey {
        try .public(pem: [UInt8](string.utf8))
    }

    public static func `public`<Data>(pem data: Data) throws -> ECDSAKey
        where Data: DataProtocol
    {
        let c = try self.load(pem: data) { bio in
            CJWTKitBoringSSL_PEM_read_bio_EC_PUBKEY(bio, nil, nil, nil)
        }
        return self.init(c)
    }

    public static func `private`(pem string: String) throws -> ECDSAKey {
        try .private(pem: [UInt8](string.utf8))
    }

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
