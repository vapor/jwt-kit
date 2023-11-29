import Foundation
import X509

struct JWTSerializer {
    func sign(
        _ payload: some JWTPayload,
        using signer: JWTSigner,
        typ: String = "JWT",
        kid: JWKIdentifier? = nil,
        cty: String? = nil,
        x5c: [String]? = nil,
        customFields: [String: JWTHeaderField] = [:],
        jsonEncoder: any JWTJSONEncoder,
        skipVerification: Bool = false
    ) async throws -> String {
        // encode header, copying header struct to mutate alg
        var header = JWTHeader()
        header.kid = kid
        header.typ = typ
        header.cty = cty
        header.alg = signer.algorithm.name
        header.customFields = customFields

        if let x5c, !x5c.isEmpty {
            if !skipVerification {
                let verifier = try X5CVerifier(rootCertificates: [x5c[0]])
                try await verifier.verifyChain(certificates: x5c)
            }
            header.x5c = try x5c.map {
                let certificate = try Certificate(pemEncoded: $0)
                return try Data(certificate.serializeAsPEM().derBytes).base64EncodedString()
            }
        }

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
