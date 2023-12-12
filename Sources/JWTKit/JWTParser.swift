import Foundation

public protocol JWTParser: Sendable {
    var encodedHeader: ArraySlice<UInt8> { get }
    var encodedPayload: ArraySlice<UInt8> { get }
    var encodedSignature: ArraySlice<UInt8> { get }
    init(encodedHeader: ArraySlice<UInt8>, encodedPayload: ArraySlice<UInt8>, encodedSignature: ArraySlice<UInt8>)
    func parseHeader(jsonDecoder: any JWTJSONDecoder) throws -> JWTHeader
    func parsePayload<Payload>(as _: Payload.Type, jsonDecoder: any JWTJSONDecoder) throws -> Payload
        where Payload: JWTPayload
}

extension JWTParser {
    init(token: some DataProtocol) throws {
        let tokenParts = token.copyBytes()
            .split(separator: .period, omittingEmptySubsequences: false)
        guard tokenParts.count == 3 else {
            throw JWTError.malformedToken
        }
        self.init(encodedHeader: tokenParts[0], encodedPayload: tokenParts[1], encodedSignature: tokenParts[2])
    }

    func verify(using algorithm: JWTAlgorithm) throws {
        guard try algorithm.verify(signature, signs: message) else {
            throw JWTError.signatureVerificationFailed
        }
    }

    private var signature: [UInt8] {
        encodedSignature.base64URLDecodedBytes()
    }

    private var message: ArraySlice<UInt8> {
        encodedHeader + [.period] + encodedPayload
    }
}

public struct DefaultJWTParser: JWTParser {
    public var encodedHeader: ArraySlice<UInt8>
    public var encodedPayload: ArraySlice<UInt8>
    public var encodedSignature: ArraySlice<UInt8>

    public init(encodedHeader: ArraySlice<UInt8>, encodedPayload: ArraySlice<UInt8>, encodedSignature: ArraySlice<UInt8>) {
        self.encodedHeader = encodedHeader
        self.encodedPayload = encodedPayload
        self.encodedSignature = encodedSignature
    }

    public func parseHeader(jsonDecoder: any JWTJSONDecoder = .defaultForJWT) throws -> JWTHeader {
        try jsonDecoder
            .decode(JWTHeader.self, from: .init(encodedHeader.base64URLDecodedBytes()))
    }

    public func parsePayload<Payload>(as _: Payload.Type, jsonDecoder: any JWTJSONDecoder = .defaultForJWT) throws -> Payload
        where Payload: JWTPayload
    {
        try jsonDecoder
            .decode(Payload.self, from: .init(encodedPayload.base64URLDecodedBytes()))
    }
}
