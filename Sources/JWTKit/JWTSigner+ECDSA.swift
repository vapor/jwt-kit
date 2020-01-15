import CJWTKitCrypto

extension JWTSigner {
    // MARK: ECDSA

    public static func es256(key: ECDSAKey) -> JWTSigner {
        return .init(algorithm: ECDSASigner(
            key: key,
            algorithm: convert(EVP_sha256()),
            name: "ES256"
        ))
    }

    public static func es384(key: ECDSAKey) -> JWTSigner {
        return .init(algorithm: ECDSASigner(
            key: key,
            algorithm: convert(EVP_sha384()),
            name: "ES384"
        ))
    }

    public static func es512(key: ECDSAKey) -> JWTSigner {
        return .init(algorithm: ECDSASigner(
            key: key,
            algorithm: convert(EVP_sha512()),
            name: "ES512"
        ))
    }
}

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
        guard let c = EC_KEY_new_by_curve_name(curve.cName) else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.newKeyByCurveFailure)
        }
        guard EC_KEY_generate_key(c) != 0 else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.generateKeyFailure)
        }

        return .init(c)
    }

    public static func `public`<Data>(pem data: Data) throws -> ECDSAKey
        where Data: DataProtocol
    {
        let c = try self.load(pem: data) { bio in
            PEM_read_bio_EC_PUBKEY(convert(bio), nil, nil, nil)
        }
        return self.init(c)
    }

    public static func `private`<Data>(pem data: Data) throws -> ECDSAKey
        where Data: DataProtocol
    {
        let c = try self.load(pem: data) { bio in
            PEM_read_bio_ECPrivateKey(convert(bio), nil, nil, nil)
        }
        return self.init(c)
    }

    let c: OpaquePointer

    init(_ c: OpaquePointer) {
        self.c = c
    }

    deinit {
        EC_KEY_free(self.c)
    }
}

// MARK: Private

private enum ECDSAError: Error {
    case newKeyByCurveFailure
    case generateKeyFailure
    case signFailure
}

private struct ECDSASigner: JWTAlgorithm, OpenSSLSigner {
    let key: ECDSAKey
    let algorithm: OpaquePointer
    let name: String

    var curveResultSize: Int {
        let curveName = EC_GROUP_get_curve_name(EC_KEY_get0_group(key.c))
        switch curveName {
        case NID_X9_62_prime256v1, NID_secp384r1:
            return 32
        case NID_secp521r1:
            return 66
        default:
            fatalError("Unsupported ECDSA key curve: \(curveName)")
        }
    }

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)
        guard let signature = ECDSA_do_sign(
            digest,
            numericCast(digest.count),
            self.key.c
        ) else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.signFailure)
        }
        defer { ECDSA_SIG_free(signature) }

        // serialize r+s values
        // see: https://tools.ietf.org/html/rfc7515#appendix-A.3
        let r = jwtkit_ECDSA_SIG_get0_r(signature)
        let s = jwtkit_ECDSA_SIG_get0_s(signature)
        let rsSize = self.curveResultSize
        var rBytes = [UInt8](repeating: 0, count: rsSize)
        var sBytes = [UInt8](repeating: 0, count: rsSize)
        let rCount = Int(BN_bn2bin(r, &rBytes))
        let sCount = Int(BN_bn2bin(s, &sBytes))
        // zero-padding may be on wrong side after write
        return rBytes.prefix(rCount).zeroPrefixed(upTo: rsSize)
            + sBytes.prefix(sCount).zeroPrefixed(upTo: rsSize)
    }

    func verify<Signature, Plaintext>(
        _ signature: Signature,
        signs plaintext: Plaintext
    ) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
        let digest = try self.digest(plaintext)

        // parse r+s values
        // see: https://tools.ietf.org/html/rfc7515#appendix-A.3
        let signatureBytes = signature.copyBytes()
        let rsSize = self.curveResultSize
        guard signatureBytes.count == rsSize * 2 else {
            return false
        }
        let signature = ECDSA_SIG_new()
        defer { ECDSA_SIG_free(signature) }

        try signatureBytes.prefix(rsSize).withUnsafeBufferPointer { r in
            try signatureBytes.suffix(rsSize).withUnsafeBufferPointer { s in
                // passing bignums to this method transfers ownership
                // (they will be freed when the signature is freed)
                guard jwtkit_ECDSA_SIG_set0(
                    signature,
                    BN_bin2bn(r.baseAddress, numericCast(rsSize), nil),
                    BN_bin2bn(s.baseAddress, numericCast(rsSize), nil)
                ) == 1 else {
                    throw JWTError.signingAlgorithmFailure(ECDSAError.signFailure)
                }
            }
        }

        return ECDSA_do_verify(
            digest,
            numericCast(digest.count),
            signature,
            self.key.c
        ) == 1
    }
}

private extension Collection where Element == UInt8 {
    func zeroPrefixed(upTo count: Int) -> [UInt8] {
        if self.count < count {
            return [UInt8](repeating: 0, count: count - self.count) + self
        } else {
            return .init(self)
        }
    }
}
