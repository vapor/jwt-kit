import class Foundation.JSONEncoder

/// A type for taking a JWT and generating, signing, and encoding it.
struct JWTSerializer {
    /// Signs a JWT with a given payload, signer, and header values.
    /// - Parameters:
    ///   - payload: The JWT's payload type. Must conform to `JWTPayload`.
    ///   - signer: The `JWTSigner` to use for the token's signature.
    ///   - typ: The signature's content type. Defaults to "JWT".
    ///   - kid: The key ID for the token (if any).
    ///   - cty: The payload's content type (if any).
    ///   - zip: The compression type to use for the payload (if any).
    func sign<Payload: JWTPayload>(
        _ payload: Payload,
        using signer: JWTSigner,
        typ: String = "JWT",
        kid: JWKIdentifier? = nil,
        cty: String? = nil,
        zip: CompressionType? = nil
    ) throws -> String {
        let jsonEncoder = JSONEncoder()
        jsonEncoder.dateEncodingStrategy = .secondsSince1970

        // encode header, copying header struct to mutate alg
        var header = JWTHeader()
        header.kid = kid
        header.typ = typ
        header.cty = cty
        header.alg = signer.algorithm.name
        header.zip = zip?.rawValue

        let headerData = try jsonEncoder.encode(header)
        let encodedHeader = headerData.base64URLEncodedBytes()

        // encode payload
        let payloadData = try jsonEncoder.encode(payload)
        let encodedPayload: [UInt8]
        
        if let compressionAlgorithm = zip {
            // if a compression algorithm was specified, compress the data before base64ing it
            let compressedData = try compressionAlgorithm.algorithm.compress(data: payloadData)
            encodedPayload = compressedData.base64URLEncodedBytes()
        } else {
            // if not, just base64 the data.
            encodedPayload = payloadData.base64URLEncodedBytes()
        }

        // combine header and payload to create signature
        let signatureData = try signer.algorithm.sign(encodedHeader + [.period] + encodedPayload)

        // yield complete jwt
        let bytes = encodedHeader
                + [.period]
                + encodedPayload
                + [.period]
                + signatureData.base64URLEncodedBytes()
        return String(decoding: bytes, as: UTF8.self)
    }
}

