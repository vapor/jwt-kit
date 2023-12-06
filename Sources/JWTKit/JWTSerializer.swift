import Foundation
import X509

public protocol JWTSerializer: Sendable {
    func makePayload(from payload: some JWTPayload, with header: JWTHeader, using jsonEncoder: any JWTJSONEncoder) throws -> Data
    func makeHeader(from header: JWTHeader, key: JWTAlgorithm) async throws -> JWTHeader
}

extension JWTSerializer {
    func sign(
        _ payload: some JWTPayload,
        with header: JWTHeader = JWTHeader(),
        using key: JWTAlgorithm,
        jsonEncoder: any JWTJSONEncoder
    ) async throws -> String {
        let header = try await self.makeHeader(from: header, key: key)
        let encodedHeader = try jsonEncoder.encode(header).base64URLEncodedBytes()

        let encodedPayload = try self.makePayload(
            from: payload, with: header, using: jsonEncoder
        ).base64URLEncodedBytes()

        let signatureData = try key.sign(encodedHeader + [.period] + encodedPayload)

        let bytes = encodedHeader
            + [.period]
            + encodedPayload
            + [.period]
            + signatureData.base64URLEncodedBytes()
        return String(decoding: bytes, as: UTF8.self)
    }
}

public struct DefaultJWTSerializer: JWTSerializer {
    public init() {}

    public func makePayload(
        from payload: some JWTPayload,
        with _: JWTHeader = JWTHeader(),
        using jsonEncoder: any JWTJSONEncoder = .defaultForJWT
    ) throws -> Data {
        try jsonEncoder.encode(payload)
    }

    public func makeHeader(
        from header: JWTHeader,
        key: JWTAlgorithm
    ) async throws -> JWTHeader {
        var newHeader = header
        if newHeader.alg?.isNull ?? true { newHeader.alg = .string(key.name) }
        if newHeader.typ?.isNull ?? true { newHeader.typ = .string("JWT") }

        if let x5c = try header.x5c?.asArray(of: String.self), !x5c.isEmpty {
            let verifier = try X5CVerifier(rootCertificates: [x5c[0]])
            try await verifier.verifyChain(certificates: x5c)
            newHeader.x5c = try .array(x5c.map {
                let certificate = try Certificate(pemEncoded: $0)
                return try JWTHeaderField.string(Data(certificate.serializeAsPEM().derBytes).base64EncodedString())
            })
        }
        return newHeader
    }
}
