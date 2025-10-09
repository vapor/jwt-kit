#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

extension String {
    package func base64URLDecodedData() -> Data? {
        var base64URL = replacingOccurrences(of: "-", with: "+")
            .replacingOccurrences(of: "_", with: "/")

        base64URL.append(contentsOf: "===".prefix((4 - (base64URL.count & 3)) & 3))

        return Data(base64Encoded: base64URL)
    }
}

extension DataProtocol {
    package func base64URLDecodedBytes() -> [UInt8] {
        Data(base64Encoded: Data(copyBytes()).base64URLUnescaped())?.copyBytes() ?? []
    }

    package func base64URLEncodedBytes() -> [UInt8] {
        Data(copyBytes()).base64EncodedData().base64URLEscaped().copyBytes()
    }
}

// MARK: Data Escape

extension Data {
    /// Converts base64-url encoded data to a base64 encoded data.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    fileprivate mutating func base64URLUnescape() {
        for idx in self.indices {
            switch self[idx] {
            case 0x2D:  // -
                self[idx] = 0x2B  // +
            case 0x5F:  // _
                self[idx] = 0x2F  // /
            default: break
            }
        }
        /// https://stackoverflow.com/questions/43499651/decode-base64url-to-base64-swift
        let padding = count % 4
        if padding > 0 {
            self += Data(repeating: 0x3D, count: 4 - count % 4)
        }
    }

    /// Converts base64 encoded data to a base64-url encoded data.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    fileprivate mutating func base64URLEscape() {
        for idx in self.indices {
            switch self[idx] {
            case 0x2B:  // +
                self[idx] = 0x2D  // -
            case 0x2F:  // /
                self[idx] = 0x5F  // _
            default: break
            }
        }
        self = split(separator: 0x3D).first ?? .init()
    }

    /// Converts base64-url encoded data to a base64 encoded data.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    fileprivate func base64URLUnescaped() -> Data {
        var data = self
        data.base64URLUnescape()
        return data
    }

    /// Converts base64 encoded data to a base64-url encoded data.
    ///
    /// https://tools.ietf.org/html/rfc4648#page-7
    fileprivate func base64URLEscaped() -> Data {
        var data = self
        data.base64URLEscape()
        return data
    }
}
