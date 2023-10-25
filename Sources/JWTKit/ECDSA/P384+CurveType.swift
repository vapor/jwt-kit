import Crypto
import Foundation

extension P384: ECDSACurveType {
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

extension P384.Signing.PublicKey: ECDSAPublicKey {
    public func isValidSignature<Signature, D>(_ signature: Signature, for data: D) throws -> Bool
        where Signature: DataProtocol, D: Digest
    {
        let signature = try P384.Signing.ECDSASignature(rawRepresentation: signature)
        return isValidSignature(signature, for: data)
    }
}

extension P384.Signing.ECDSASignature: ECDSASignature {}
extension P384.Signing.PrivateKey: ECDSAPrivateKey {}

public typealias P384Key = ECDSAKey<P384>
