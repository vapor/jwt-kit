import Foundation
import NIO
import NIOFoundationCompat

extension Data {
    func compressed(using algorithm: NIOCompression.Algorithm) throws -> Data {
        let allocator = ByteBufferAllocator()
        var buffer = allocator.buffer(capacity: self.count)
        buffer.writeBytes(self)

        var compressor = NIOCompression.Compressor()
        compressor.initialize(encoding: algorithm)

        let compressedBuffer = compressor.compress(inputBuffer: &buffer, allocator: allocator, finalise: true)
        compressor.shutdown()

        return Data(buffer: compressedBuffer)
    }
    
    func decompressed(using algorithm: NIOHTTPDecompression.CompressionAlgorithm, limit: NIOHTTPDecompression.DecompressionLimit = .none) throws -> Data? {
        var decompressor = NIOHTTPDecompression.Decompressor(limit: limit)
        try decompressor.initializeDecoder(encoding: algorithm)

        let bufferAllocator = ByteBufferAllocator()
        var inputBuffer = bufferAllocator.buffer(capacity: self.count)
        inputBuffer.writeBytes(self)

        var outputBuffer = bufferAllocator.buffer(capacity: inputBuffer.readableBytes * 2)
        let result = try decompressor.decompress(part: &inputBuffer, buffer: &outputBuffer, compressedLength: self.count)

        decompressor.deinitializeDecoder()

        guard result.complete else {
            return nil
        }

        return Data(buffer: outputBuffer)
    }
}
