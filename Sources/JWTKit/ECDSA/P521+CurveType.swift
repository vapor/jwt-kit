import Crypto
import Foundation

extension P521: CurveType {
    public typealias Signature = P521.Signing.ECDSASignature
    public typealias PrivateKey = P521.Signing.PrivateKey

    public static let curve: ECDSACurve = .p521
}

extension P521.Signing.PublicKey: ECDSAPublicKey {
    public func isValidSignature<Signature, Digest>(_ signature: Signature, for data: Digest) throws -> Bool
        where Signature: DataProtocol, Digest: DataProtocol
    {
        let signature = try P521.Signing.ECDSASignature(rawRepresentation: signature)
        return isValidSignature(signature, for: data)
    }
}

extension P521.Signing.ECDSASignature: ECDSASignature {}
extension P521.Signing.PrivateKey: ECDSAPrivateKey {}

public typealias P521Key = ECDSAKey<P521>
