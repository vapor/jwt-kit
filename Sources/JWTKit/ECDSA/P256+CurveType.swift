import Crypto

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

// TODO: Remove @unchecked Sendable when Crypto is updated to use Sendable
extension P256: ECDSACurveType {
    public typealias Signature = P256.Signing.ECDSASignature
    public typealias PrivateKey = P256.Signing.PrivateKey

    public static let curve: ECDSACurve = .p256

    /// Specifies the byte ranges in which the X and Y coordinates of an ECDSA public key appear for the P256 curve.
    /// For P256, the public key is typically 65 bytes long: a single byte prefix (usually 0x04 for uncompressed keys), followed by
    /// 32 bytes for the X coordinate, and then 32 bytes for the Y coordinate.
    ///
    /// Thus:
    /// - The X coordinate spans bytes 1 through 32 (byte 0 is for the prefix).
    /// - The Y coordinate spans bytes 33 through 64.
    public static let byteRanges: (x: Range<Int>, y: Range<Int>) = (1..<33, 33..<65)

    public struct SigningAlgorithm: ECDSASigningAlgorithm {
        public static let name = "ES256"
        public static let digestAlgorithm: DigestAlgorithm = .sha256
    }
}

// TODO: Remove @unchecked Sendable when Crypto is updated to use Sendable
extension P256.Signing.PublicKey: ECDSAPublicKey {
    /// Verifies that the P256 key signature is valid for the given digest.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify.
    ///   - digest: The digest to verify the signature against.
    /// - Returns: True if the signature is valid for the given digest, false otherwise.
    /// - Throws: If there is a problem verifying the signature.
    public func isValidSignature(_ signature: some DataProtocol, for data: some Digest) throws -> Bool {
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        return isValidSignature(signature, for: data)
    }
}

// TODO: Remove @unchecked Sendable when Crypto is updated to use Sendable
extension P256.Signing.PrivateKey: ECDSAPrivateKey, @unchecked @retroactive Sendable {}
extension P256.Signing.ECDSASignature: ECDSASignature, @unchecked @retroactive Sendable {}
extension P256.Signing.PublicKey: @unchecked @retroactive Sendable {}
extension P256: @unchecked @retroactive Sendable {}

public typealias ES256PublicKey = ECDSA.PublicKey<P256>
public typealias ES256PrivateKey = ECDSA.PrivateKey<P256>
