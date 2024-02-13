import Foundation

public protocol JWTParser: Sendable {
    var jsonDecoder: JWTJSONDecoder { get set }
    func parse<Payload>(_ token: some DataProtocol, as: Payload.Type) throws -> (header: JWTHeader, payload: Payload, signature: Data) where Payload: JWTPayload
}

extension JWTParser {
    public func getTokenParts(_ token: some DataProtocol) throws -> (header: ArraySlice<UInt8>, payload: ArraySlice<UInt8>, signature: ArraySlice<UInt8>) {
        let tokenParts = token.copyBytes().split(separator: .period, omittingEmptySubsequences: false)
        
        guard tokenParts.count == 3 else {
            throw JWTError.malformedToken
        }
        
        return (tokenParts[0], tokenParts[1], tokenParts[2])
    }
}

extension JWTParser {
    func parseHeader(_ token: some DataProtocol) throws -> JWTHeader {
        let tokenParts = token.copyBytes().split(separator: .period, omittingEmptySubsequences: false)
        
        guard tokenParts.count == 3 else {
            throw JWTError.malformedToken
        }
        
        return try jsonDecoder.decode(JWTHeader.self, from: .init(tokenParts[0].base64URLDecodedBytes()))
    }
}

public struct DefaultJWTParser: JWTParser {
    public var jsonDecoder: JWTJSONDecoder = .defaultForJWT
    
    public init(jsonDecoder: JWTJSONDecoder = .defaultForJWT) {
        self.jsonDecoder = jsonDecoder
    }
    
    public func parse<Payload>(_ token: some DataProtocol, as: Payload.Type) throws -> (header: JWTHeader, payload: Payload, signature: Data)
        where Payload: JWTPayload
    {
        let (encodedHeader, encodedPayload, encodedSignature) = try getTokenParts(token)
        
        let header = try jsonDecoder.decode(JWTHeader.self, from: .init(encodedHeader.base64URLDecodedBytes()))
        let payload = try jsonDecoder.decode(Payload.self, from: .init(encodedPayload.base64URLDecodedBytes()))
        let signature = Data(encodedSignature.base64URLDecodedBytes())
        
        return (header: header, payload: payload, signature: signature)
    }
}
