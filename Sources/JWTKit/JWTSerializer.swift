import Foundation
import X509

protocol JWTSerializer {
    func sign(
        _ payload: some JWTPayload,
        with header: JWTHeader,
        using key: JWTAlgorithm,
        jsonEncoder: any JWTJSONEncoder,
        skipVerification: Bool
    ) async throws -> String
}

extension JWTSerializer {
    func sign(
        _ payload: some JWTPayload,
        with header: JWTHeader = JWTHeader(),
        using key: JWTAlgorithm,
        jsonEncoder: any JWTJSONEncoder = .defaultForJWT,
        skipVerification: Bool = false
    ) async throws -> String {
        try await self.sign(
            payload,
            with: header,
            using: key,
            jsonEncoder: jsonEncoder,
            skipVerification: skipVerification
        )
    }
}

struct DefaultJWTSerializer: JWTSerializer {
    func sign(
        _ payload: some JWTPayload,
        with header: JWTHeader = JWTHeader(),
        using key: JWTAlgorithm,
        jsonEncoder: any JWTJSONEncoder,
        skipVerification: Bool = false
    ) async throws -> String {
        // encode header, copying header struct to mutate alg
        var newHeader = header
        if newHeader.alg?.isNull ?? true { newHeader.alg = .string(key.name) }
        if newHeader.typ?.isNull ?? true { newHeader.typ = .string("JWT") }

        if let x5c = try header.x5c?.asArray(of: String.self), !x5c.isEmpty {
            if !skipVerification {
                let verifier = try X5CVerifier(rootCertificates: [x5c[0]])
                try await verifier.verifyChain(certificates: x5c)
            }
            newHeader.x5c = try .array(x5c.map {
                let certificate = try Certificate(pemEncoded: $0)
                return try JWTHeaderField.string(Data(certificate.serializeAsPEM().derBytes).base64EncodedString())
            })
        }

        let headerData = try jsonEncoder.encode(newHeader)
        let encodedHeader = headerData.base64URLEncodedBytes()

        // encode payload
        let payloadData = try jsonEncoder.encode(payload)
        let encodedPayload = payloadData.base64URLEncodedBytes()

        // combine header and payload to create signature
        let signatureData = try key.sign(encodedHeader + [.period] + encodedPayload)

        // yield complete jwt
        let bytes = encodedHeader
            + [.period]
            + encodedPayload
            + [.period]
            + signatureData.base64URLEncodedBytes()
        return String(decoding: bytes, as: UTF8.self)
    }
}
