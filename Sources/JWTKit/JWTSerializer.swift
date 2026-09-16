import ExtrasBase64
import SwiftASN1
import X509

#if !canImport(Darwin)
public import FoundationEssentials
#else
public import Foundation
#endif

public protocol JWTSerializer: Sendable {
    var jsonEncoder: any JWTJSONEncoder { get }
    func serialize(_ payload: some JWTPayload, header: JWTHeader) throws -> Data
}

extension JWTSerializer {
    public func makeHeader(from header: JWTHeader, key: any JWTAlgorithm) async throws -> JWTHeader {
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

    func makeSigningInput(payload: some JWTPayload, header: JWTHeader, key: some JWTAlgorithm) async throws -> [UInt8] {
        let header = try await self.makeHeader(from: header, key: key)
        let headerJSON = try jsonEncoder.encode(header)
        let encodedHeaderLength = Base64.base64URLEncodedLength(bytesCount: headerJSON.count)

        var signingInput = [UInt8]()

        if let serializer = self as? DefaultJWTSerializer {
            // Encode the payload straight into the buffer instead of going through
            // the `Data` that `serialize(_:header:)` has to return.
            let payloadJSON = try serializer.jsonEncoder.encode(payload)
            let encodedPayloadLength = Base64.base64URLEncodedLength(bytesCount: payloadJSON.count)
            signingInput.reserveCapacity(encodedHeaderLength + 1 + encodedPayloadLength + 1 + Self.reservedSignatureLength)
            signingInput.appendBase64URLEncoded(headerJSON.span)
            signingInput.append(.period)
            signingInput.appendBase64URLEncoded(payloadJSON.span)
        } else {
            let encodedPayload = try self.serialize(payload, header: header)
            signingInput.reserveCapacity(encodedHeaderLength + 1 + encodedPayload.count + 1 + Self.reservedSignatureLength)
            signingInput.appendBase64URLEncoded(headerJSON.span)
            signingInput.append(.period)
            signingInput.append(contentsOf: encodedPayload)
        }

        return signingInput
    }

    /// Room reserved for the encoded signature: a 384-byte (RSA-3072) signature is 512 characters,
    /// which also covers every HMAC, ECDSA and EdDSA size. Larger signatures grow the buffer once.
    private static var reservedSignatureLength: Int { 512 }

    func sign(_ payload: some JWTPayload, with header: JWTHeader = JWTHeader(), using key: some JWTAlgorithm) async throws -> String {
        var token = try await makeSigningInput(payload: payload, header: header, key: key)

        let signature = try key.sign(token)[...]

        token.append(.period)
        token.appendBase64URLEncoded(signature.span)
        return String(decoding: token, as: UTF8.self)
    }
}

public struct DefaultJWTSerializer: JWTSerializer {
    public var jsonEncoder: any JWTJSONEncoder = .defaultForJWT

    public init(jsonEncoder: any JWTJSONEncoder = .defaultForJWT) {
        self.jsonEncoder = jsonEncoder
    }

    public func serialize(_ payload: some JWTPayload, header: JWTHeader = JWTHeader()) throws -> Data {
        try Data(jsonEncoder.encode(payload).base64URLEncodedBytes())
    }
}
