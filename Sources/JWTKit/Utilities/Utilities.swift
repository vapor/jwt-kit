#if !canImport(Darwin)
public import FoundationEssentials
#else
public import Foundation
#endif

extension DataProtocol {
    public func copyBytes() -> [UInt8] {
        if let array = self.withContiguousStorageIfAvailable({ buffer in
            unsafe [UInt8](buffer)
        }) {
            return array
        } else {
            let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: self.count)
            unsafe self.copyBytes(to: buffer)
            defer { unsafe buffer.deallocate() }
            return unsafe [UInt8](buffer)
        }
    }
}

extension UInt8 {
    static var period: UInt8 {
        return Character(".").asciiValue!
    }
}
