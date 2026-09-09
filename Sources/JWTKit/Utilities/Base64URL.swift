import ExtrasBase64

extension Collection where Element == UInt8 {
    package func base64URLEncodedBytes() -> [UInt8] {
        Base64.encodeToBytes(bytes: self, options: [.base64UrlAlphabet, .omitPaddingCharacter])
    }

    package func base64URLEncodedString() -> String {
        Base64.encodeToString(bytes: self, options: [.base64UrlAlphabet, .omitPaddingCharacter])
    }

    package func base64URLDecodedBytes() throws -> [UInt8] {
        try Base64.decode(bytes: self, options: [.base64UrlAlphabet, .omitPaddingCharacter])
    }
}

extension String {
    package func base64URLDecodedBytes() throws -> [UInt8] {
        try self.utf8.base64URLDecodedBytes()
    }
}
