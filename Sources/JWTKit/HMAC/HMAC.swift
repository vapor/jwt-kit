@preconcurrency import Crypto

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

public struct HMACKey: Sendable {
    let key: SymmetricKey

    public init(from string: some StringProtocol) {
        self.init(from: [UInt8](string.utf8))
    }

    public init(from data: some DataProtocol) {
        self.key = .init(data: data.copyBytes())
    }

    public init(key: SymmetricKey) {
        self.key = key
    }
}

extension HMACKey: ExpressibleByStringLiteral {
    public init(stringLiteral value: StringLiteralType) {
        self.init(from: value)
    }
}
