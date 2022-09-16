import class Foundation.JSONEncoder

struct JWTSerializer {
    func sign<Payload>(
        _ payload: Payload,
        using signer: JWTSigner,
        typ: String = "JWT",
        kid: JWKIdentifier? = nil,
        cty: String? = nil,
        zip: CompressionType? = nil
    ) throws -> String
        where Payload: JWTPayload
    {
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

