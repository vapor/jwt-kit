import Crypto
import Foundation

enum DigestAlgorithm {
    case sha256
    case sha384
    case sha512
}

protocol CryptoSigner {
    var algorithm: DigestAlgorithm { get }
}

private enum OpenSSLError: Error {
    case digestInitializationFailure
    case digestUpdateFailure
    case digestFinalizationFailure
    case bioPutsFailure
    case bioConversionFailure
}

extension CryptoSigner {
    func digest<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        switch algorithm {
        case .sha256:
            return SHA256.hash(data: plaintext).map { $0 }
        case .sha384:
            return SHA384.hash(data: plaintext).map { $0 }
        case .sha512:
            return SHA512.hash(data: plaintext).map { $0 }
        }
    }
}

enum KeyType {
    case `public`
    case `private`
    case certificate
}
