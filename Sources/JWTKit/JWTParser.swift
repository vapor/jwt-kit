#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

public protocol JWTParser: Sendable {
    var jsonDecoder: JWTJSONDecoder { get set }
    func parse<Payload>(_ token: some DataProtocol, as: Payload.Type) throws -> (
        header: JWTHeader, payload: Payload, signature: Data
    ) where Payload: JWTPayload
}

extension JWTParser {
    public func getTokenParts(_ token: some DataProtocol) throws -> (
        header: ArraySlice<UInt8>, payload: ArraySlice<UInt8>, signature: ArraySlice<UInt8>
    ) {
        let tokenParts = token.copyBytes().split(
            separator: .period, omittingEmptySubsequences: false
        )

        guard tokenParts.count == 3 else {
            throw JWTError.malformedToken(reason: "Token is not split in 3 parts")
        }

        return (tokenParts[0], tokenParts[1], tokenParts[2])
    }
}

extension JWTParser {
    func parseHeader(_ token: some DataProtocol) throws -> JWTHeader {
        let tokenParts = token.copyBytes().split(separator: .period, omittingEmptySubsequences: false)

        guard tokenParts.count == 3 else {
            throw JWTError.malformedToken(reason: "Token parts count is not 3.")
        }

        do {
            return try jsonDecoder.decode(JWTHeader.self, from: .init(tokenParts[0].base64URLDecodedBytes()))
        } catch {
            throw JWTError.malformedToken(reason: "Couldn't decode header from JWT with error: \(String(describing: error)).")
        }
    }
}

public struct DefaultJWTParser: JWTParser {
    public var jsonDecoder: JWTJSONDecoder = .defaultForJWT

    public init(jsonDecoder: JWTJSONDecoder = .defaultForJWT) {
        self.jsonDecoder = jsonDecoder
    }

    public func parse<Payload>(_ token: some DataProtocol, as: Payload.Type) throws -> (
        header: JWTHeader, payload: Payload, signature: Data
    ) where Payload: JWTPayload {
        let (encodedHeader, encodedPayload, encodedSignature) = try getTokenParts(token)

        let header: JWTHeader
        let payload: Payload
        let signature: Data

        func isUTF8(_ bytes: [UInt8]) -> Bool {
            String(bytes: bytes, encoding: .utf8) != nil
        }

        let headerBytes = encodedHeader.base64URLDecodedBytes()
        let payloadBytes = encodedPayload.base64URLDecodedBytes()

        guard isUTF8(headerBytes) && isUTF8(payloadBytes) else {
            throw JWTError.malformedToken(reason: "Header and payload must be UTF-8 encoded.")
        }

        do {
            header = try jsonDecoder.decode(JWTHeader.self, from: .init(headerBytes))
            payload = try jsonDecoder.decode(Payload.self, from: .init(payloadBytes))
            signature = Data(encodedSignature.base64URLDecodedBytes())
        } catch {
            throw JWTError.malformedToken(reason: "Couldn't decode JWT with error: \(String(describing: error))")
        }

        return (header: header, payload: payload, signature: signature)
    }
}
