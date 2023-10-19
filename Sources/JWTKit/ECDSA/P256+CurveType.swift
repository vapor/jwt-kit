import Crypto
import Foundation

extension P256: CurveType {
    public typealias Signature = P256.Signing.ECDSASignature
    public typealias PrivateKey = P256.Signing.PrivateKey

    public static let curve: ECDSACurve = .p256

    public static let byteRanges: (x: Range<Int>, y: Range<Int>) = (1 ..< 33, 33 ..< 65)
}

extension P256.Signing.PublicKey: ECDSAPublicKey {
    public func isValidSignature<Signature, D>(_ signature: Signature, for data: D) throws -> Bool
        where Signature: DataProtocol, D: Digest
    {
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        return isValidSignature(signature, for: data)
    }
}

extension P256.Signing.ECDSASignature: ECDSASignature {}
extension P256.Signing.PrivateKey: ECDSAPrivateKey {}

public typealias P256Key = ECDSAKey<P256>
