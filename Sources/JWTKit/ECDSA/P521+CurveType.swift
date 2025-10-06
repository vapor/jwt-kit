import Crypto

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

// TODO: Remove @unchecked Sendable when Crypto is updated to use Sendable
extension P521: ECDSACurveType {
    public typealias Signature = P521.Signing.ECDSASignature
    public typealias PrivateKey = P521.Signing.PrivateKey

    public static let curve: ECDSACurve = .p521

    /// Specifies the byte ranges in which the X and Y coordinates of an ECDSA public key appear for the P521 curve.
    /// For P521, the public key is a bit tricky because 521 bits is not a multiple of 8, but it's typically represented as 66 bytes
    /// for each coordinate with leading zeros as needed. The public key is hence 133 bytes long: a single byte prefix (usually 0x04
    /// for uncompressed keys), followed by 66 bytes for the X coordinate, and then 66 bytes for the Y coordinate.
    ///
    /// Thus:
    /// - The X coordinate spans bytes 1 through 66.
    /// - The Y coordinate spans bytes 67 through 132.
    public static let byteRanges: (x: Range<Int>, y: Range<Int>) = (1..<67, 67..<133)

    public enum SigningAlgorithm: ECDSASigningAlgorithm {
        public static let name = "ES512"
        public static let digestAlgorithm: DigestAlgorithm = .sha512
    }
}

// TODO: Remove @unchecked Sendable when Crypto is updated to use Sendable
extension P521.Signing.PublicKey: ECDSAPublicKey {
    /// Verifies that the P256 key signature is valid for the given digest.
    ///
    /// - Parameters:
    ///   - signature: The signature to verify.
    ///   - digest: The digest to verify the signature against.
    /// - Returns: True if the signature is valid for the given digest, false otherwise.
    /// - Throws: If there is a problem verifying the signature.
    public func isValidSignature(_ signature: some DataProtocol, for data: some Digest) throws -> Bool {
        let signature = try P521.Signing.ECDSASignature(rawRepresentation: signature)
        return isValidSignature(signature, for: data)
    }
}

extension P521.Signing.PrivateKey: ECDSAPrivateKey, @unchecked @retroactive Sendable {}
extension P521.Signing.ECDSASignature: ECDSASignature, @unchecked @retroactive Sendable {}
extension P521.Signing.PublicKey: @unchecked @retroactive Sendable {}
extension P521: @unchecked @retroactive Sendable {}

public typealias ES512PublicKey = ECDSA.PublicKey<P521>
public typealias ES512PrivateKey = ECDSA.PrivateKey<P521>
