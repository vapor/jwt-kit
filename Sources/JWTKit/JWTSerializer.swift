import X509

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

public protocol JWTSerializer: Sendable {
    var jsonEncoder: any JWTJSONEncoder { get }
    func serialize(_ payload: some JWTPayload, header: JWTHeader) throws -> Data
}

extension JWTSerializer {
    public func makeHeader(from header: JWTHeader, key: JWTAlgorithm) async throws -> JWTHeader {
        var newHeader = header

        newHeader.alg = newHeader.alg ?? key.name
        newHeader.typ = newHeader.typ ?? "JWT"

        if let x5c = newHeader.x5c, !x5c.isEmpty {
            let verifier = try X5CVerifier(rootCertificates: [x5c[0]])
            let certs = try x5c.map { try Certificate(pemEncoded: $0) }
            _ = try await verifier.verifyChain(certificates: certs)

            newHeader.x5c = try x5c.map { cert in
                let certificate = try Certificate(pemEncoded: cert)
                let derBytes = try Data(certificate.serializeAsPEM().derBytes)
                return derBytes.base64EncodedString()
            }
        }

        return newHeader
    }

    func makeSigningInput(payload: some JWTPayload, header: JWTHeader, key: some JWTAlgorithm) async throws -> Data {
        let header = try await self.makeHeader(from: header, key: key)
        let encodedHeader = try jsonEncoder.encode(header).base64URLEncodedBytes()

        let encodedPayload = try self.serialize(payload, header: header)

        return encodedHeader + [.period] + encodedPayload
    }

    func sign(_ payload: some JWTPayload, with header: JWTHeader = JWTHeader(), using key: some JWTAlgorithm) async throws -> String {
        let signingInput = try await makeSigningInput(payload: payload, header: header, key: key)

        let signatureData = try key.sign(signingInput)

        let bytes = signingInput + [.period] + signatureData.base64URLEncodedBytes()
        return String(decoding: bytes, as: UTF8.self)
    }
}

public struct DefaultJWTSerializer: JWTSerializer {
    public var jsonEncoder: JWTJSONEncoder = .defaultForJWT

    public init(jsonEncoder: JWTJSONEncoder = .defaultForJWT) {
        self.jsonEncoder = jsonEncoder
    }

    public func serialize(_ payload: some JWTPayload, header: JWTHeader = JWTHeader()) throws -> Data {
        try Data(jsonEncoder.encode(payload).base64URLEncodedBytes())
    }
}
