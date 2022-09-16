import Foundation
import class SWCompression.Deflate
import protocol SWCompression.DecompressionAlgorithm
import protocol SWCompression.CompressionAlgorithm

/// The supported compression types for a JWT's body.
public enum CompressionTypes: String {
    /// Deflate (Gzip) compression.
    case deflate = "DEF"
}

/// Types that can both compress and decompress data.
typealias CompressableAlgorithm = DecompressionAlgorithm & CompressionAlgorithm

extension CompressionTypes {
    /// The decompression algorithm for the compression type.
    var algorithm: CompressableAlgorithm.Type {
        switch self {
            case .deflate:
                return Deflate.self
        }
    }
}

