import Crypto

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

public struct DigestAlgorithm: Sendable, Equatable {
    enum Backing {
        case sha256
        case sha384
        case sha512
    }

    let backing: Backing

    public static let sha256 = Self(backing: .sha256)
    public static let sha384 = Self(backing: .sha384)
    public static let sha512 = Self(backing: .sha512)
}

protocol CryptoSigner: Sendable {
    var algorithm: DigestAlgorithm { get }
}

private enum CryptoError: Error {
    case digestInitializationFailure
    case digestUpdateFailure
    case digestFinalizationFailure
    case bioPutsFailure
    case bioConversionFailure
}

extension CryptoSigner {
    func digest(_ plaintext: some DataProtocol) throws -> any Digest {
        switch algorithm.backing {
        case .sha256:
            SHA256.hash(data: plaintext)
        case .sha384:
            SHA384.hash(data: plaintext)
        case .sha512:
            SHA512.hash(data: plaintext)
        }
    }
}

enum KeyType {
    case `public`
    case `private`
}
