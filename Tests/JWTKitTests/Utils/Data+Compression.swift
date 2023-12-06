import Compression
import Foundation

extension Data {
    private func compression(isEncode: Bool, algorithm: compression_algorithm) -> Data {
        withUnsafeBytes { (rawBuffer: UnsafeRawBufferPointer) in
            let buffer: UnsafeBufferPointer<UInt8> = rawBuffer.bindMemory(to: UInt8.self)
            let pointer: UnsafePointer<UInt8> = buffer.baseAddress!
            let destCapacity = 1_000_000
            let destinationBuffer = UnsafeMutablePointer<UInt8>.allocate(capacity: destCapacity)
            defer { destinationBuffer.deallocate() }
            let destinationBytes: Int
            if isEncode {
                destinationBytes = compression_encode_buffer(destinationBuffer, destCapacity, pointer, count, nil, algorithm)
            } else {
                destinationBytes = compression_decode_buffer(destinationBuffer, destCapacity, pointer, count, nil, algorithm)
            }
            guard destinationBytes != 0 else {
                fatalError("Compression failed")
            }
            return Data(bytes: destinationBuffer, count: destinationBytes)
        }
    }

    func deflate() -> Data {
        compression(isEncode: true, algorithm: COMPRESSION_ZLIB)
    }

    func inflate() -> Data {
        compression(isEncode: false, algorithm: COMPRESSION_ZLIB)
    }
}
