import class Foundation.JSONEncoder

struct JWTSerializer {
    func sign<Payload>(
        _ payload: Payload,
        using signer: JWTSigner,
        typ: String = "JWT",
        kid: JWKIdentifier? = nil,
        cty: String? = nil
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

        let headerData = try jsonEncoder.encode(header)
        let encodedHeader = headerData.base64URLEncodedBytes()

        // encode payload
        let payloadData = try jsonEncoder.encode(payload)
        let encodedPayload = payloadData.base64URLEncodedBytes()

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

