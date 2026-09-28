package import ExtrasBase64

#if !canImport(Darwin)
package import FoundationEssentials
#else
package import Foundation
#endif

private let base64URLEncoding: Base64.EncodingOptions = [.base64UrlAlphabet, .omitPaddingCharacter]
private let base64URLDecoding: Base64.DecodingOptions = [.base64UrlAlphabet, .omitPaddingCharacter]

extension Base64 {
    package static func base64URLEncodedLength(bytesCount: Int) -> Int {
        encodedLength(bytesCount: bytesCount, options: base64URLEncoding)
    }
}

extension Span where Element == UInt8 {
    package func base64URLDecodedBytes() throws -> [UInt8] {
        try Base64.decode(bytes: self, options: base64URLDecoding)
    }

    package func base64URLDecodedData() throws -> Data {
        var data = Data(count: Base64.decodedLength(bytesCount: count))
        var output = data.mutableSpan
        let decodedCount = try Base64.decode(bytes: self, into: &output, options: base64URLDecoding)
        data.count = decodedCount
        return data
    }
}

extension Array where Element == UInt8 {
    package mutating func appendBase64URLEncoded(_ bytes: Span<UInt8>) {
        #if compiler(>=6.3)
        append(addingCapacity: Base64.base64URLEncodedLength(bytesCount: bytes.count)) { output in
            Base64.encode(bytes: bytes, into: &output, options: base64URLEncoding)
        }
        #else
        append(contentsOf: Base64.encodeToBytes(bytes: bytes, options: base64URLEncoding))
        #endif
    }
}

extension Collection where Element == UInt8 {
    package func base64URLEncodedBytes() -> [UInt8] {
        Base64.encodeToBytes(bytes: self, options: base64URLEncoding)
    }

    package func base64URLEncodedString() -> String {
        Base64.encodeToString(bytes: self, options: base64URLEncoding)
    }

    package func base64URLDecodedBytes() throws -> [UInt8] {
        try Base64.decode(bytes: self, options: base64URLDecoding)
    }
}

extension String {
    package func base64URLDecodedBytes() throws -> [UInt8] {
        try self.utf8.base64URLDecodedBytes()
    }
}
