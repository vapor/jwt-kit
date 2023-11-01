import Crypto
import Foundation

public extension JWTKeyCollection {
    // MARK: 256

    @discardableResult
    func addHS256(
        key: String,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        addHS256(key: [UInt8](key.utf8), kid: kid, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    @discardableResult
    func addHS256(
        key: some DataProtocol,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        let symmetricKey = SymmetricKey(data: key.copyBytes())
        return addHS256(key: symmetricKey, kid: kid, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    @discardableResult
    func addHS256(
        key: SymmetricKey,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(algorithm: HMACSigner<SHA256>(key: key, name: "HS256"), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder), for: kid)
    }
}

public extension JWTKeyCollection {
    // MARK: 384

    @discardableResult
    func addHS384(
        key: String,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        addHS384(key: [UInt8](key.utf8), kid: kid, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    @discardableResult
    func addHS384(
        key: some DataProtocol,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        let symmetricKey = SymmetricKey(data: key.copyBytes())
        return addHS384(key: symmetricKey, kid: kid, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    @discardableResult
    func addHS384(
        key: SymmetricKey,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(algorithm: HMACSigner<SHA384>(key: key, name: "HS384"), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder), for: kid)
    }
}

public extension JWTKeyCollection {
    // MARK: 512

    @discardableResult
    func addHS512(
        key: String,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        addHS512(key: [UInt8](key.utf8), kid: kid, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    @discardableResult
    func addHS512(
        key: some DataProtocol,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        let symmetricKey = SymmetricKey(data: key.copyBytes())
        return addHS512(key: symmetricKey, kid: kid, jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

    @discardableResult
    func addHS512(
        key: SymmetricKey,
        kid: JWKIdentifier? = nil,
        jsonEncoder: (any JWTJSONEncoder)? = nil,
        jsonDecoder: (any JWTJSONDecoder)? = nil
    ) -> Self {
        add(.init(algorithm: HMACSigner<SHA512>(key: key, name: "HS512"), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder), for: kid)
    }
}
