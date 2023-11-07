/// The header (details) used for signing and processing the JWT.
public struct JWTHeader: Codable, Sendable {
    /// The algorithm used with the signing.
    public var alg: String?

    /// The Signature's Content Type.
    public var typ: String?

    /// The Payload's Content Type.
    public var cty: String?

    /// Critical fields.
    public var crit: [String]?

    /// The JWT key identifier.
    public var kid: JWKIdentifier?

    /// The x5c certificate chain.
    public var x5c: [String]?
}
