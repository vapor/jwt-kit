import CJWTKitBoringSSL

public final class ECDSAKey: OpenSSLKey {
    public enum Curve {
        case p256
        case p384
        case p521

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

    deinit {
        CJWTKitBoringSSL_EC_KEY_free(self.c)
    }
    
    public static func components(x: String, y: String, curve: Curve = .p521) throws -> ECDSAKey {
        // TODO: originally curve = NID_X9_62_prime256v1
        guard let c = CJWTKitBoringSSL_EC_KEY_new_by_curve_name(curve.cName) else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.newKeyByCurveFailure)
        }

         guard let bnX = BN.convert(x) else {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "Unable to interpret x as BN");
        }
        guard let bnY = BN.convert(y) else {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "Unable to interpret y as BN");
        }

         if (1 != CJWTKitBoringSSL_EC_KEY_set_public_key_affine_coordinates(c, bnX.c, bnY.c)) {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "Unable to set public key");
        }

         return .init(c)
    }

     public func getParameters() throws -> Parameters {
        let group: OpaquePointer = CJWTKitBoringSSL_EC_KEY_get0_group(self.c);
        let pubKey: OpaquePointer = CJWTKitBoringSSL_EC_KEY_get0_public_key(self.c);

         let bnX = BN();
        let bnY = BN();
        if (CJWTKitBoringSSL_EC_POINT_get_affine_coordinates_GFp(group, pubKey, bnX.c, bnY.c, nil) != 1) {
            throw JWTError.generic(identifier: "ecCoordinates", reason: "EC coordinates retrieval failed");
        }

         return Parameters(x: bnX.toBase64(), y: bnY.toBase64());
    }


     public struct Parameters {
        public let x: String;
        public let y: String;
    }


}
