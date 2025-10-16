#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@_spi(PostQuantum)
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public protocol MLDSAKey: Sendable {
    associatedtype MLDSAType: JWTKit.MLDSAType
}

@_spi(PostQuantum)
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public protocol MLDSAPublicKey: Sendable {
    associatedtype MLDSAType

    init(rawRepresentation: some DataProtocol) throws
    var rawRepresentation: Data { get }
    func isValidSignature<S: DataProtocol, D: DataProtocol>(_ signature: S, for data: D) -> Bool
    func isValidSignature<S: DataProtocol, D: DataProtocol, C: DataProtocol>(
        _ signature: S, for data: D, context: C
    ) -> Bool
}

@_spi(PostQuantum)
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public protocol MLDSAPrivateKey: Sendable {
    associatedtype MLDSAType
    associatedtype PublicKey: MLDSAPublicKey

    var seedRepresentation: Data { get }
    var publicKey: PublicKey { get }
    init<D>(seedRepresentation: D, publicKey: PublicKey?) throws where D: DataProtocol
    func signature<D: DataProtocol>(for data: D) throws -> Data
    func signature<D: DataProtocol, C: DataProtocol>(for data: D, context: C) throws -> Data
}
