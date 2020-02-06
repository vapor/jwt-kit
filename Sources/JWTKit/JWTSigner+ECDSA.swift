import CJWTKitCrypto
import Crypto
import Foundation

extension JWTSigner {
    // MARK: ECDSA

    public static func es256(key: ECDSAKey) -> JWTSigner {
        return .init(algorithm: ECDSASigner<P256>(
            key: key,
            algorithm: convert(EVP_sha256()),
            name: "ES256"
        ))
    }

    public static func es384(key: ECDSAKey) -> JWTSigner {
        return .init(algorithm: ECDSASigner<P384>(
            key: key,
            algorithm: convert(EVP_sha384()),
            name: "ES384"
        ))
    }

    public static func es512(key: ECDSAKey) -> JWTSigner {
        return .init(algorithm: ECDSASigner<P521>(
            key: key,
            algorithm: convert(EVP_sha512()),
            name: "ES512"
        ))
    }
}

public protocol ECDSASignature {}
extension P256.Signing.ECDSASignature: ECDSASignature {}
extension P384.Signing.ECDSASignature: ECDSASignature {}
extension P521.Signing.ECDSASignature: ECDSASignature {}

public protocol EllipticCurve {
    static func signature<D>(rawRepresentation: D) throws -> ECDSASignature where D : DataProtocol
}
extension P256: EllipticCurve {
    public static func signature<D>(rawRepresentation: D) throws -> ECDSASignature where D : DataProtocol {
        return try Signing.ECDSASignature(rawRepresentation: rawRepresentation)
    }
}
extension P384: EllipticCurve {
    public static func signature<D>(rawRepresentation: D) throws -> ECDSASignature where D : DataProtocol {
        return try Signing.ECDSASignature(rawRepresentation: rawRepresentation)
    }
}
extension P521: EllipticCurve {
    public static func signature<D>(rawRepresentation: D) throws -> ECDSASignature where D : DataProtocol {
        return try Signing.ECDSASignature(rawRepresentation: rawRepresentation)
    }
}

public final class ECDSAKey: OpenSSLKey  {
    
    // See https://github.com/apple/swift-crypto/blob/64a1a98e47e6643e6d43d30b87a244483b51d8ad/Tests/CryptoTests/ECDH/BoringSSL/secpECDH_Runner_boring.swift#L64-L83
    private static func convertFromPem(_ derBytes: [UInt8]) throws -> P256.Signing.PublicKey {
        // Bad news everybody. Using the EC DER parsing from OpenSSL limits our ability to tell the difference
        // between an invalid SPKI layout (which we don't care about, as the production library doesn't support DER-encoded
        // EC keys) and a SPKI layout that is syntactically valid but doesn't represent a valid point on the curve. We _do_
        // care about passing this into the production library.
        //
        // This means we've only one option: we have to implement "just enough" ASN.1.
        var derBytes = derBytes[...]
        let spki = try ASN1SubjectPublicKeyInfo(fromASN1: &derBytes)
        guard derBytes.count == 0, spki.algorithm.algorithm == ASN1ObjectIdentifier.AlgorithmIdentifier.idEcPublicKey else {
            throw ECDSAError.parseSPKIFailure
        }

        // Ok, the bitstring we are holding is the X963 representation of the public key. Try to create it.
        let key = try P256.Signing.PublicKey(x963Representation: spki.subjectPublicKey)
        return key
    }
    
    public static func generate() throws -> ECDSAKey {
        let key = P256.Signing.PrivateKey()
        return .init(key)
    }

    public static func `public`(pem: String) throws -> ECDSAKey {
        let strippedPem = pem.replacingOccurrences(of: "-----BEGIN PUBLIC KEY-----\n", with: "").replacingOccurrences(of: "-----END PUBLIC KEY-----", with: "").replacingOccurrences(of: "\n", with: "")
        
        guard let data = Data(base64Encoded: strippedPem) else {
            throw ECDSAError.parseSPKIFailure
        }
        
        let key = try ECDSAKey.convertFromPem(data.copyBytes())
        return .init(publicKey: key)
    }

    public static func `private`(der: [UInt8]) throws -> ECDSAKey {
        let key = try P256.Signing.PrivateKey(x963Representation: der)
        return .init(key)
    }

    let privateKey: P256.Signing.PrivateKey?
    let publicKey: P256.Signing.PublicKey

    init(_ privateKey: P256.Signing.PrivateKey) {
        self.privateKey = privateKey
        self.publicKey = privateKey.publicKey
    }
    
    init(publicKey: P256.Signing.PublicKey) {
        self.publicKey = publicKey
        self.privateKey = nil
    }
}

// MARK: Private

private enum ECDSAError: Error {
    case missingPrivateKeyFailure
    case signFailure
    case parseSPKIFailure
}

private struct ECDSASigner<CurveType>: JWTAlgorithm, OpenSSLSigner where CurveType: EllipticCurve {
    let key: ECDSAKey
    let algorithm: OpaquePointer
    let name: String

    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
//        let digest = try self.digest(plaintext)
//        guard let signature = ECDSA_do_sign(
//            digest,
//            numericCast(digest.count),
//            self.key.c
//        ) else {
//            throw JWTError.signingAlgorithmFailure(ECDSAError.signFailure)
//        }
//        defer { ECDSA_SIG_free(signature) }
//
//        // serialize r+s values
//        // see: https://tools.ietf.org/html/rfc7515#appendix-A.3
//        var rBytes = [UInt8](repeating: 0, count: 32)
//        var sBytes = [UInt8](repeating: 0, count: 32)
//        let rCount = Int(BN_bn2bin(jwtkit_ECDSA_SIG_get0_r(signature), &rBytes))
//        let sCount = Int(BN_bn2bin(jwtkit_ECDSA_SIG_get0_s(signature), &sBytes))
//
//        // BN_bn2bin can return < 32 bytes which will result in the data
//        // being zero-padded on the wrong side
//        return .init(
//            [UInt8](repeating: 0, count: 32 - rCount) +
//            rBytes[0..<rCount] +
//            [UInt8](repeating: 0, count: 32 - sCount) +
//            sBytes[0..<sCount]
//        )
        guard let privateKey = key.privateKey else {
            throw JWTError.signingAlgorithmFailure(ECDSAError.missingPrivateKeyFailure)
        }
        let signature = try privateKey.signature(for: plaintext)
        return signature.rawRepresentation.copyBytes()
    }

    func verify<Signature, Plaintext>(
        _ signature: Signature,
        signs plaintext: Plaintext
    ) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
//        let digest = try self.digest(plaintext)
//
//        // parse r+s values
//        // see: https://tools.ietf.org/html/rfc7515#appendix-A.3
//        let signatureBytes = signature.copyBytes()
//        guard signatureBytes.count == 64 else {
//            return false
//        }
//
//        let signature = ECDSA_SIG_new()
//        defer { ECDSA_SIG_free(signature) }
//
//        try signatureBytes[0..<32].withUnsafeBufferPointer { r in
//            try signatureBytes[32..<64].withUnsafeBufferPointer { s in
//                // passing bignums to this method transfers ownership
//                // (they will be freed when the signature is freed)
//                guard jwtkit_ECDSA_SIG_set0(
//                    signature,
//                    BN_bin2bn(r.baseAddress, 32, nil),
//                    BN_bin2bn(s.baseAddress, 32, nil)
//                ) == 1 else {
//                    throw JWTError.signingAlgorithmFailure(ECDSAError.signFailure)
//                }
//            }
//        }
//
//        return ECDSA_do_verify(
//            digest,
//            numericCast(digest.count),
//            signature,
//            self.key.c
//        ) == 1
//        let signature = try CurveType.signature(rawRepresentation: signature)
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        return self.key.publicKey.isValidSignature(signature, for: plaintext)
    }
}
