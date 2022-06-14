import Foundation
@_implementationOnly import CJWTKitBoringSSL

class BigNumber {
    let c: UnsafeMutablePointer<BIGNUM>?;

    public init() {
        self.c = CJWTKitBoringSSL_BN_new();
    }

    init(_ ptr: OpaquePointer) {
        self.c = UnsafeMutablePointer<BIGNUM>(ptr);
    }

    deinit {
        CJWTKitBoringSSL_BN_free(self.c);
    }

    public static func convert(_ bnBase64: String) -> BigNumber? {
        guard let data = Data(base64Encoded: bnBase64) else {
            return nil
        }

        let c = data.withUnsafeBytes { (p: UnsafeRawBufferPointer) -> OpaquePointer in
            return OpaquePointer(CJWTKitBoringSSL_BN_bin2bn(p.baseAddress?.assumingMemoryBound(to: UInt8.self), p.count, nil))
        }
        return BigNumber(c)
    }

    public convenience init?(base64URL: String) {
        guard let data = base64URL.data(using: .utf8)?.base64URLDecodedBytes() else {
            return nil
        }

        let c = data.withUnsafeBytes { (p: UnsafeRawBufferPointer) -> OpaquePointer in
            return OpaquePointer(CJWTKitBoringSSL_BN_bin2bn(p.baseAddress?.assumingMemoryBound(to: UInt8.self), p.count, nil))
        }
        self.init(c)
    }

    public func toBase64(_ size: Int = 1000) -> String {
        let pBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: size)
        defer { pBuffer.deallocate() }

        let actualBytes = Int(CJWTKitBoringSSL_BN_bn2bin(self.c, pBuffer))
        let data = Data(bytes: pBuffer, count: actualBytes)
        return data.base64EncodedString()
    }

    public func toBase64URL() -> String {
        let bytes = CJWTKitBoringSSL_BN_num_bytes(self.c)
        let pBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: Int(bytes))
        defer { pBuffer.deallocate() }

        let actualBytes = Int(CJWTKitBoringSSL_BN_bn2bin(self.c, pBuffer))
        let data = Data(bytes: pBuffer, count: actualBytes)
        return String.init(decoding: data.base64URLEncodedBytes(), as: UTF8.self)
    }
}
