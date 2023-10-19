import Crypto
import Foundation

extension P521: CurveType {
    public typealias Signature = P521.Signing.ECDSASignature
    public typealias PrivateKey = P521.Signing.PrivateKey

    public static let curve: ECDSACurve = .p521

    public static let byteRanges: (x: Range<Int>, y: Range<Int>) = (1 ..< 67, 67 ..< 133)
}

extension P521.Signing.PublicKey: ECDSAPublicKey {
    public func isValidSignature<Signature, D>(_ signature: Signature, for data: D) throws -> Bool
        where Signature: DataProtocol, D: Digest
    {
        let signature = try P521.Signing.ECDSASignature(rawRepresentation: signature)
        return isValidSignature(signature, for: data)
    }
}

extension P521.Signing.ECDSASignature: ECDSASignature {}
extension P521.Signing.PrivateKey: ECDSAPrivateKey {}

public typealias P521Key = ECDSAKey<P521>
