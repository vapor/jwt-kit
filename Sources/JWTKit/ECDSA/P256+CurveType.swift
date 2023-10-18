import Crypto
import Foundation

extension P256: CurveType {
    public typealias Signature = P256.Signing.ECDSASignature
    public typealias PrivateKey = P256.Signing.PrivateKey

    public static let curve: ECDSACurve = .p256
}

extension P256.Signing.PublicKey: ECDSAPublicKey {
    public func isValidSignature<Signature, Digest>(_ signature: Signature, for data: Digest) throws -> Bool
        where Signature: DataProtocol, Digest: DataProtocol
    {
        let signature = try P256.Signing.ECDSASignature(rawRepresentation: signature)
        return isValidSignature(signature, for: data)
    }
}

extension P256.Signing.PrivateKey: ECDSAPrivateKey {
    public typealias PublicKey = P256.Signing.PublicKey

    public func signature<D>(for data: D) throws -> Data where D: DataProtocol {
        try signature(for: data).rawRepresentation
    }
}

public typealias P256Key = ECDSAKey<P256>
