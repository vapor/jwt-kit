import Crypto
import Foundation

extension P384: CurveType {
    public typealias Signature = P384.Signing.ECDSASignature
    public typealias PrivateKey = P384.Signing.PrivateKey

    public static let curve: ECDSACurve = .p384

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
