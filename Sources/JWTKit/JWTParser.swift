import Foundation

struct JWTParser: Sendable {
    let encodedHeader: ArraySlice<UInt8>
    let encodedPayload: ArraySlice<UInt8>
    let encodedSignature: ArraySlice<UInt8>

    init(token: some DataProtocol) throws {
        let tokenParts = token.copyBytes()
            .split(separator: .period, omittingEmptySubsequences: false)
        guard tokenParts.count == 3 else {
            throw JWTError.malformedToken
        }
        encodedHeader = tokenParts[0]
        encodedPayload = tokenParts[1]
        encodedSignature = tokenParts[2]
    }

    func header(jsonDecoder: any JWTJSONDecoder = .defaultForJWT) throws -> JWTHeader {
        try jsonDecoder
            .decode(JWTHeader.self, from: .init(encodedHeader.base64URLDecodedBytes()))
    }

    func payload<Payload>(as _: Payload.Type, jsonDecoder: any JWTJSONDecoder = .defaultForJWT) throws -> Payload
        where Payload: JWTPayload
    {
        try jsonDecoder
            .decode(Payload.self, from: .init(encodedPayload.base64URLDecodedBytes()))
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
