struct JWTSerializer {
    func sign(
        _ payload: some JWTPayload,
        using signer: JWTSigner,
        typ: String = "JWT",
        kid: JWKIdentifier? = nil,
        cty: String? = nil,
        b64: Bool = true,
        jsonEncoder: any JWTJSONEncoder
    ) throws -> String {
        // encode header, copying header struct to mutate alg
        var header = JWTHeader()
        header.kid = kid
        header.typ = typ
        header.cty = cty
        header.alg = signer.algorithm.name
        header.b64 = b64

        let headerData = try jsonEncoder.encode(header)
        let encodedHeader = headerData.base64URLEncodedBytes()

        // encode payload
        let payloadData = try jsonEncoder.encode(payload)
        let encodedPayload: [UInt8]
        if b64 == true {
            encodedPayload = payloadData.base64URLEncodedBytes()
        } else {
            encodedPayload = payloadData.copyBytes()
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
