import CryptoExtras

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

@_spi(PostQuantum)
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public enum MLDSA: Sendable {}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA {
    public struct PublicKey<KeyType>: MLDSAKey where KeyType: MLDSAType {
        public typealias MLDSAType = KeyType

        typealias PublicKey = KeyType.PrivateKey.PublicKey

        let backing: any MLDSAPublicKey

        public init(backing: some MLDSAPublicKey) {
            self.backing = backing
        }

        public init(rawRepresentation: some DataProtocol) throws {
            self.backing = try PublicKey(rawRepresentation: rawRepresentation)
        }
    }
}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA {
    public struct PrivateKey<KeyType>: MLDSAKey where KeyType: MLDSAType {
        public typealias MLDSAType = KeyType

        typealias PrivateKey = KeyType.PrivateKey

        let backing: any MLDSAPrivateKey

        public var publicKey: MLDSA.PublicKey<KeyType> {
            .init(backing: self.backing.publicKey)
        }

        public init(backing: some MLDSAPrivateKey) {
            self.backing = backing
        }

        public init(seedRepresentation: some DataProtocol, publicKey: KeyType.PrivateKey.PublicKey? = nil) throws {
            self.backing = try PrivateKey(seedRepresentation: seedRepresentation, publicKey: publicKey)
        }
    }
}
