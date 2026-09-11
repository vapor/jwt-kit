#if !canImport(Darwin)
public import FoundationEssentials
#else
public import Foundation
#endif

public protocol JWTParser: Sendable {
    var jsonDecoder: any JWTJSONDecoder { get set }
    func parse<Payload>(_ token: some DataProtocol, as: Payload.Type) throws -> (
        header: JWTHeader, payload: Payload, signature: Data
    ) where Payload: JWTPayload
}

extension JWTParser {
    public func getTokenParts(_ token: some DataProtocol) throws -> (
        header: ArraySlice<UInt8>, payload: ArraySlice<UInt8>, signature: ArraySlice<UInt8>
    ) {
        try getTokenParts(Array(token))
    }

    func getTokenParts(_ token: [UInt8]) throws -> (
        header: ArraySlice<UInt8>, payload: ArraySlice<UInt8>, signature: ArraySlice<UInt8>
    ) {
        let tokenParts = token.split(
            separator: .period, omittingEmptySubsequences: false
        )

        guard tokenParts.count == 3 else {
            throw JWTError.malformedToken(reason: "Token is not split in 3 parts")
        }

        return (tokenParts[0], tokenParts[1], tokenParts[2])
    }
}

extension JWTParser {
    func parseHeader(_ token: [UInt8]) throws -> JWTHeader {
        let tokenParts = token.split(separator: .period, omittingEmptySubsequences: false)

        guard tokenParts.count == 3 else {
            throw JWTError.malformedToken(reason: "Token parts count is not 3.")
        }

        do {
            let decoded = try tokenParts[0].base64URLDecodedBytes()
            return try jsonDecoder.decode(JWTHeader.self, from: Data(decoded))
        } catch {
            throw JWTError.malformedToken(reason: "Couldn't decode header from JWT with error: \(String(describing: error)).")
        }
    }
}

public struct DefaultJWTParser: JWTParser {
    public var jsonDecoder: any JWTJSONDecoder = .defaultForJWT

    public init(jsonDecoder: any JWTJSONDecoder = .defaultForJWT) {
        self.jsonDecoder = jsonDecoder
    }

    public func parse<Payload>(
        _ token: some DataProtocol, as: Payload.Type
    ) throws -> (header: JWTHeader, payload: Payload, signature: Data) where Payload: JWTPayload {
        let (encodedHeader, encodedPayload, encodedSignature) = try getTokenParts(token)

        let headerBytes: [UInt8]
        let payloadBytes: [UInt8]

        do {
            headerBytes = try encodedHeader.base64URLDecodedBytes()
            payloadBytes = try encodedPayload.base64URLDecodedBytes()
        } catch {
            throw JWTError.malformedToken(reason: "Header and payload must be UTF-8 encoded.")
        }

        let header: JWTHeader
        let payload: Payload
        let signature: [UInt8]

        do {
            header = try jsonDecoder.decode(JWTHeader.self, from: .init(headerBytes))
            payload = try jsonDecoder.decode(Payload.self, from: .init(payloadBytes))
            signature = try encodedSignature.base64URLDecodedBytes()
        } catch {
            throw JWTError.malformedToken(reason: "Couldn't decode JWT with error: \(String(describing: error))")
        }

        return (header: header, payload: payload, signature: Data(signature))
    }

    func parsePayload<Payload>(
        _ encodedPayload: ArraySlice<UInt8>, as: Payload.Type
    ) throws -> Payload where Payload: JWTPayload {
        let payload: Payload
        let payloadBytes = try encodedPayload.base64URLDecodedBytes()

        do {
            payload = try jsonDecoder.decode(Payload.self, from: .init(payloadBytes))
        } catch {
            throw JWTError.malformedToken(reason: "Couldn't decode JWT payload with error: \(String(describing: error))")
        }

        return payload
    }
}
