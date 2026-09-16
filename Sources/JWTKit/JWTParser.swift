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
        let parts = try TokenParts(Array(token))
        return (parts.header, parts.payload, parts.signature)
    }
}

extension JWTParser {
    func parseHeader(_ token: [UInt8]) throws -> JWTHeader {
        let parts = try TokenParts(token)

        do {
            return try jsonDecoder.decode(JWTHeader.self, from: parts.header.span.base64URLDecodedData())
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
        let parts = try TokenParts(Array(token))

        let headerData: Data
        let payloadData: Data

        do {
            headerData = try parts.header.span.base64URLDecodedData()
            payloadData = try parts.payload.span.base64URLDecodedData()
        } catch {
            throw JWTError.malformedToken(reason: "Header and payload must be UTF-8 encoded.")
        }

        let header: JWTHeader
        let payload: Payload
        let signature: [UInt8]

        do {
            header = try jsonDecoder.decode(JWTHeader.self, from: headerData)
            payload = try jsonDecoder.decode(Payload.self, from: payloadData)
            signature = try parts.signature.span.base64URLDecodedBytes()
        } catch {
            throw JWTError.malformedToken(reason: "Couldn't decode JWT with error: \(String(describing: error))")
        }

        return (header: header, payload: payload, signature: Data(signature))
    }

    func parsePayload<Payload>(
        _ encodedPayload: ArraySlice<UInt8>, as: Payload.Type
    ) throws -> Payload where Payload: JWTPayload {
        let payload: Payload
        let payloadData = try encodedPayload.span.base64URLDecodedData()

        do {
            payload = try jsonDecoder.decode(Payload.self, from: payloadData)
        } catch {
            throw JWTError.malformedToken(reason: "Couldn't decode JWT payload with error: \(String(describing: error))")
        }

        return payload
    }
}
