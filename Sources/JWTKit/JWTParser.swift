import class Foundation.JSONDecoder
import struct Foundation.Data
import class SWCompression.Deflate

/// A type for parsing JWTs from raw data.
struct JWTParser {
    let encodedHeader: ArraySlice<UInt8>
    let encodedPayload: ArraySlice<UInt8>
    let encodedSignature: ArraySlice<UInt8>

    /// Initialize a JWTParser with raw token data.
    /// - Parameters:
    ///   - token: The raw data of the token (must conform to `DataProtocol`).
    init<Token: DataProtocol>(token: Token) throws {
        let tokenParts = token.copyBytes()
            .split(separator: .period, omittingEmptySubsequences: false)
        guard tokenParts.count == 3 else {
            throw JWTError.malformedToken
        }
        self.encodedHeader = tokenParts[0]
        self.encodedPayload = tokenParts[1]
        self.encodedSignature = tokenParts[2]
    }

    /// Parses the header data into a `JWTHeader`.
    func header() throws -> JWTHeader {
        try self.jsonDecoder()
            .decode(JWTHeader.self, from: .init(self.encodedHeader.base64URLDecodedBytes()))
    }

    /// Parses the payload data into a given payload type, accounting for compression specified in the header.
    /// - Parameters:
    ///   - payload: The type of payload to parse to.
    func payload<Payload>(as payload: Payload.Type) throws -> Payload
        where Payload: JWTPayload
    {
        var decodedPayload = Data(self.encodedPayload.base64URLDecodedBytes())

        if let compressionType = try self.header().zip {
            guard let compressionType = CompressionType(rawValue: compressionType) else {
                throw JWTError.invalidCompression(algorithm: compressionType)
            }
            decodedPayload = try compressionType.algorithm.decompress(data: decodedPayload)
        }

        return try self.jsonDecoder()
            .decode(Payload.self, from: decodedPayload)
    }

    /// Verify the parsed token using a given signer.
    /// - Parameters:
    ///   - signer: The `JWTSigner` to use for verification.
    func verify(using signer: JWTSigner) throws {
        guard try signer.algorithm.verify(self.signature, signs: self.message) else {
            throw JWTError.signatureVerifictionFailed
        }
    }

    /// The raw bytes of the token's signature.
    private var signature: [UInt8] {
        self.encodedSignature.base64URLDecodedBytes()
    }

    /// The message of the token (without the signature).
    private var message: ArraySlice<UInt8> {
        self.encodedHeader + [.period] + self.encodedPayload
    }

    /// A `JSONDecoder` with the proper settings for JWTs.
    private func jsonDecoder() -> JSONDecoder {
        let jsonDecoder = JSONDecoder()
        jsonDecoder.dateDecodingStrategy = .secondsSince1970
        return jsonDecoder
    }
}
