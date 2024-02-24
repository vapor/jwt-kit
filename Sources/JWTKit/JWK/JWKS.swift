/// A JSON Web Key Set.
///
/// A JSON object that represents a set of JWKs.
/// Read specification (RFC 7517) https://tools.ietf.org/html/rfc7517.
public struct JWKS: Codable, Sendable {
    /// All JSON Web Keys
    public var keys: [JWK]

    public init(keys: [JWK]) {
        self.keys = keys
    }

    /// Retrieves the desired key from the JSON Web Key Set
    /// - Parameters:
    ///   - identifier: The `kid` value to lookup.
    ///   - type: The `kty` value.
    public func find(identifier: String, type: JWK.KeyType) -> JWK? {
        self.keys.first(where: { $0.keyType == type && $0.keyIdentifier?.string == identifier })
    }

    /// Retrieves the desired key from the JSON Web Key Set
    /// - Parameters:
    ///   - identifier: The `kid` value to lookup.
    ///   - type: The `kty` value.
    public func find(identifier: JWKIdentifier, type: JWK.KeyType) -> JWK? {
        self.find(identifier: identifier.string, type: type)
    }

    /// Retrieves the desired keys from the JSON Web Key Set
    /// Multiple keys can have the same `kid` if they have different `kty` values.
    /// - Parameter identifier: The `kid` value to lookup.
    public func find(identifier: JWKIdentifier) -> [JWK]? {
        self.find(identifier: identifier.string)
    }

    /// Retrieves the desired keys from the JSON Web Key Set
    /// Multiple keys can have the same `kid` if they have different `kty` values.
    /// - Parameter identifier: The `kid` value to lookup.
    public func find(identifier: String) -> [JWK]? {
        self.keys.filter { $0.keyIdentifier?.string == identifier }
    }
}
