//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2020-2021 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import CNIOExtrasZlib
import NIOCore

/// Namespace for compression code.
public enum NIOCompression {

    /// Which algorithm should be used for compression.
    public struct Algorithm: CustomStringConvertible, Equatable, Sendable {
        fileprivate enum AlgorithmEnum: String {
            case gzip
            case deflate
        }
        fileprivate let algorithm: AlgorithmEnum
        
        /// return as String
        public var description: String { return algorithm.rawValue }

        /// `gzip` method
        public static let gzip = Algorithm(algorithm: .gzip)
        /// `deflate` method
        public static let deflate = Algorithm(algorithm: .deflate)
    }

    /// Error types for ``NIOCompression``
    public struct Error: Swift.Error, CustomStringConvertible, Equatable {
        fileprivate enum ErrorEnum: String {
            case uncompressedWritesPending
            case noDataToWrite
        }
        fileprivate let error: ErrorEnum
        
        /// return as String
        public var description: String { return error.rawValue }

        /// There were writes pending which were not processed before shutdown.
        public static let uncompressedWritesPending = Error(error: .uncompressedWritesPending)
        /// Currently never used.
        public static let noDataToWrite = Error(error: .noDataToWrite)
    }

    /// Data compression utility.
    struct Compressor {
        private var stream = z_stream()
        var isActive = false

        init() { }

        /// Set up the encoder for compressing data according to a specific
        /// algorithm.
        mutating func initialize(encoding: Algorithm) {
            assert(!isActive)
            isActive = true
            // zlib docs say: The application must initialize zalloc, zfree and opaque before calling the init function.
            stream.zalloc = nil
            stream.zfree = nil
            stream.opaque = nil

            let windowBits: Int32
            switch encoding.algorithm {
            case .deflate:
                windowBits = 15
            case .gzip:
                windowBits = 16 + 15
            }

            let rc = CNIOExtrasZlib_deflateInit2(&stream, Z_DEFAULT_COMPRESSION, Z_DEFLATED, windowBits, 8, Z_DEFAULT_STRATEGY)
            precondition(rc == Z_OK, "Unexpected return from zlib init: \(rc)")
        }

        mutating func compress(inputBuffer: inout ByteBuffer, allocator: ByteBufferAllocator, finalise: Bool) -> ByteBuffer {
            assert(isActive)
            let flags = finalise ? Z_FINISH : Z_SYNC_FLUSH
            // don't compress an empty buffer if we aren't finishing the compress
            guard inputBuffer.readableBytes > 0 || finalise == true else { return allocator.buffer(capacity: 0) }
            // deflateBound() provides an upper limit on the number of bytes the input can
            // compress to. We add 5 bytes to handle the fact that Z_SYNC_FLUSH will append
            // an empty stored block that is 5 bytes long.
            // From zlib docs (https://www.zlib.net/manual.html)
            // If the parameter flush is set to Z_SYNC_FLUSH, all pending output is flushed to the output buffer and the output is
            // aligned on a byte boundary, so that the decompressor can get all input data available so far. (In particular avail_in
            // is zero after the call if enough output space has been provided before the call.) Flushing may degrade compression for
            // some compression algorithms and so it should be used only when necessary. This completes the current deflate block and
            // follows it with an empty stored block that is three bits plus filler bits to the next byte, followed by four bytes
            // (00 00 ff ff).
            let bufferSize = Int(deflateBound(&stream, UInt(inputBuffer.readableBytes)))
            var outputBuffer = allocator.buffer(capacity: bufferSize + 5)
            stream.oneShotDeflate(from: &inputBuffer, to: &outputBuffer, flag: flags)
            return outputBuffer
        }
        
        mutating func shutdown() {
            assert(isActive)
            isActive = false
            deflateEnd(&stream)
        }
        
        mutating func shutdownIfActive() {
            if isActive {
                isActive = false
                deflateEnd(&stream)
            }
        }
    }
}

extension z_stream {
    /// Executes deflate from one buffer to another buffer. The advantage of this method is that it
    /// will ensure that the stream is "safe" after each call (that is, that the stream does not have
    /// pointers to byte buffers any longer).
    mutating func oneShotDeflate(from: inout ByteBuffer, to: inout ByteBuffer, flag: Int32) {
        defer {
            self.avail_in = 0
            self.next_in = nil
            self.avail_out = 0
            self.next_out = nil
        }

        from.readWithUnsafeMutableReadableBytes { dataPtr in
            let typedPtr = dataPtr.baseAddress!.assumingMemoryBound(to: UInt8.self)
            let typedDataPtr = UnsafeMutableBufferPointer(start: typedPtr,
                                                          count: dataPtr.count)

            self.avail_in = UInt32(typedDataPtr.count)
            self.next_in = typedDataPtr.baseAddress!

            let rc = deflateToBuffer(buffer: &to, flag: flag)
            precondition(rc == Z_OK || rc == Z_STREAM_END, "One-shot compression failed: \(rc)")

            return typedDataPtr.count - Int(self.avail_in)
        }
    }

    /// A private function that sets the deflate target buffer and then calls deflate.
    /// This relies on having the input set by the previous caller: it will use whatever input was
    /// configured.
    private mutating func deflateToBuffer(buffer: inout ByteBuffer, flag: Int32) -> Int32 {
        var rc = Z_OK

        buffer.writeWithUnsafeMutableBytes(minimumWritableBytes: buffer.capacity) { outputPtr in
            let typedOutputPtr = UnsafeMutableBufferPointer(start: outputPtr.baseAddress!.assumingMemoryBound(to: UInt8.self),
                                                            count: outputPtr.count)
            self.avail_out = UInt32(typedOutputPtr.count)
            self.next_out = typedOutputPtr.baseAddress!
            rc = deflate(&self, flag)
            return typedOutputPtr.count - Int(self.avail_out)
        }

        return rc
    }
}
