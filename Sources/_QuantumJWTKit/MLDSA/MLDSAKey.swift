#if canImport(FoundationEssentials)
    import FoundationEssentials
#else
    import Foundation
#endif

public protocol MLDSAKey: Sendable {
    associatedtype MLDSAType: _QuantumJWTKit.MLDSAType
}

public protocol MLDSAPublicKey: Sendable {
    associatedtype MLDSAType

    init(rawRepresentation: some DataProtocol) throws
    var rawRepresentation: Data { get }
    func isValidSignature<S: DataProtocol, D: DataProtocol>(_ signature: S, for data: D) -> Bool
    func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(
        _ signature: S, for data: D, context: C
    ) -> Bool
}

public protocol MLDSAPrivateKey: Sendable {
    associatedtype MLDSAType
    associatedtype PublicKey: MLDSAPublicKey

    var seedRepresentation: Data { get }
    var publicKey: PublicKey { get }
    init(seedRepresentation: some DataProtocol) throws
    func signature<D: DataProtocol>(for data: D) throws -> Data
    func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data
}
