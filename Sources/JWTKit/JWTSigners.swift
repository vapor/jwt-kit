import class Foundation.JSONEncoder
import class Foundation.JSONDecoder
import struct Foundation.Data

/// A collection of signers labeled by `kid`.
public final class JWTSigners {
    /// Internal storage.
    private var storage: [JWKIdentifier: JWTSigner]

    private var `default`: JWTSigner?

    /// Create a new `JWTSigners`.
    public init() {
        self.storage = [:]
    }

    /// Adds a new signer.
    public func use(
        _ signer: JWTSigner,
        kid: JWKIdentifier? = nil,
        isDefault: Bool? = nil
    ) {
        if let kid = kid {
            self.storage[kid] = signer
        }
        if self.default == nil && isDefault != false {
            self.default = signer
        }
    }

    /// Gets a signer for the supplied `kid`, if one exists.
    public func get(kid: JWKIdentifier? = nil) -> JWTSigner? {
        if let kid = kid {
            return self.storage[kid]
        } else {
            return self.default
        }
    }

    public func verify<Message, Payload>(
        _ message: Message,
        as payload: Payload.Type = Payload.self
    ) throws -> Payload
        where Message: DataProtocol, Payload: JWTPayload
    {
        let messageParts = message.copyBytes().split(separator: .period)
        guard messageParts.count == 3 else {
            throw JWTError.malformedToken
        }

        let encodedHeader = messageParts[0]
        let encodedPayload = messageParts[1]
        let encodedSignature = messageParts[2]

        let jsonDecoder = JSONDecoder()
        jsonDecoder.dateDecodingStrategy = .secondsSince1970
        let header = try jsonDecoder.decode(JWTHeader.self, from: Data(encodedHeader.base64URLDecodedBytes()))
        guard let signer = self.get(kid: header.kid) else {
            fatalError()
        }
        let payload = try jsonDecoder.decode(Payload.self, from: Data(encodedPayload.base64URLDecodedBytes()))
        guard try signer.algorithm.verify(
            encodedSignature.base64URLDecodedBytes(),
            signs: encodedHeader + [.period] + encodedPayload
        ) else {
            throw JWTError.signatureVerifictionFailed
        }
        try payload.verify(using: signer)
        return payload
    }

    public func unverified<Message, Payload>(
        _ message: Message,
        as payload: Payload.Type = Payload.self
    ) throws -> Payload
        where Message: DataProtocol, Payload: JWTPayload
    {
        let messageParts = message.copyBytes().split(separator: .period)
        guard messageParts.count == 3 else {
            throw JWTError.malformedToken
        }
        let encodedPayload = messageParts[1]
        let jsonDecoder = JSONDecoder()
        jsonDecoder.dateDecodingStrategy = .secondsSince1970
        let payload = try jsonDecoder.decode(Payload.self, from: Data(encodedPayload.base64URLDecodedBytes()))
        return payload
    }

    public func sign<Payload>(
        _ payload: Payload,
        kid: JWKIdentifier? = nil
    ) throws -> String
        where Payload: JWTPayload
    {
        guard let signer = self.get(kid: kid) else {
            fatalError()
        }
        return try signer.sign(payload, kid: kid)
    }
}
