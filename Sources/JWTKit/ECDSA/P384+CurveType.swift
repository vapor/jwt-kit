import Crypto
import Foundation

// TODO: Remove @unchecked Sendable when Crypto is updated to use Sendable
extension P384: ECDSACurveType, @unchecked Sendable {
    public typealias Signature = P384.Signing.ECDSASignature
    public typealias PrivateKey = P384.Signing.PrivateKey

    public static let curve: ECDSACurve = .p384

    /// Specifies the byte ranges in which the X and Y coordinates of an ECDSA public key appear for the P384 curve.
    /// For P384, the public key is typically 97 bytes long: a single byte prefix (usually 0x04 for uncompressed keys), followed by
    /// 48 bytes for the X coordinate, and then 48 bytes for the Y coordinate.
    ///
    /// Thus:
    /// - The X coordinate spans bytes 1 through 48.
    /// - The Y coordinate spans bytes 49 through 96.
    public static let byteRanges: (x: Range<Int>, y: Range<Int>) = (1 ..< 49, 49 ..< 97)
}

// TODO: Remove @unchecked Sendable when Crypto is updated to use Sendable
extension P384.Signing.PublicKey: ECDSAPublicKey, @unchecked Sendable {
    /// Verifies that the P384 key signature is valid for the given digest.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify.
    ///   - digest: The digest to verify the signature against.
    /// - Returns: True if the signature is valid for the given digest, false otherwise.
    /// - Throws: If there is a problem verifying the signature.
    public func isValidSignature(_ signature: some DataProtocol, for data: some Digest) throws -> Bool {
        let signature = try P384.Signing.ECDSASignature(rawRepresentation: signature)
        return isValidSignature(signature, for: data)
    }
}

// TODO: Remove @unchecked Sendable when Crypto is updated to use Sendable
extension P384.Signing.PrivateKey: ECDSAPrivateKey, @unchecked Sendable {}
// TODO: Remove @unchecked Sendable when Crypto is updated to use Sendable
extension P384.Signing.ECDSASignature: ECDSASignature, @unchecked Sendable {}

public typealias ES384Key = ECDSAKey<P384>
