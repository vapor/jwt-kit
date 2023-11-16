import Crypto
import Foundation

enum DigestAlgorithm {
    case sha256
    case sha384
    case sha512
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
        switch algorithm {
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
