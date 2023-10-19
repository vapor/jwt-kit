import Crypto
import Foundation

extension P384: CurveType {
    public typealias Signature = P384.Signing.ECDSASignature
    public typealias PrivateKey = P384.Signing.PrivateKey

    public static let curve: ECDSACurve = .p384
}

extension P384.Signing.PublicKey: ECDSAPublicKey {
    public func isValidSignature<Signature, Digest>(_ signature: Signature, for data: Digest) throws -> Bool
        where Signature: DataProtocol, Digest: DataProtocol
    {
        let signature = try P384.Signing.ECDSASignature(rawRepresentation: signature)
        return isValidSignature(signature, for: data)
    }
}

extension P384.Signing.ECDSASignature: ECDSASignature {}
extension P384.Signing.PrivateKey: ECDSAPrivateKey {}

public typealias P384Key = ECDSAKey<P384>
