import Foundation

struct JWTParser {
    let encodedHeader: ArraySlice<UInt8>
    let encodedPayload: ArraySlice<UInt8>
    let encodedSignature: ArraySlice<UInt8>

    init<Token>(token: Token) throws
        where Token: DataProtocol
    {
        let tokenParts = token.copyBytes()
            .split(separator: .period, omittingEmptySubsequences: false)
        guard tokenParts.count == 3 else {
            throw JWTError.malformedToken
        }
        self.encodedHeader = tokenParts[0]
        self.encodedPayload = tokenParts[1]
        self.encodedSignature = tokenParts[2]
    }

    func header(jsonDecoder: any JWTJSONDecoder) throws -> JWTHeader {
        try jsonDecoder
            .decode(JWTHeader.self, from: .init(self.encodedHeader.base64URLDecodedBytes()))
    }

    func payload<Payload>(as payload: Payload.Type, jsonDecoder: any JWTJSONDecoder) throws -> Payload
        where Payload: JWTPayload
    {
        try jsonDecoder
            .decode(Payload.self, from: .init(self.encodedPayload.base64URLDecodedBytes()))
    }

    func verify(using signer: JWTSigner) throws {
        guard try signer.algorithm.verify(self.signature, signs: self.message) else {
            throw JWTError.signatureVerifictionFailed
        }
    }

    private var signature: [UInt8] {
        self.encodedSignature.base64URLDecodedBytes()
    }

    private var message: ArraySlice<UInt8> {
        self.encodedHeader + [.period] + self.encodedPayload
    }
}
