#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

extension DataProtocol {
    public func copyBytes() -> [UInt8] {
        if let array = self.withContiguousStorageIfAvailable({ buffer in
            [UInt8](buffer)
        }) {
            return array
        } else {
            let buffer = UnsafeMutableBufferPointer<UInt8>.allocate(capacity: self.count)
            self.copyBytes(to: buffer)
            defer { buffer.deallocate() }
            return [UInt8](buffer)
        }
    }
}

extension UInt8 {
    static var period: UInt8 {
        return Character(".").asciiValue!
    }
}
