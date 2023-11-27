/// The header (details) used for signing and processing the JWT.
package struct JWTHeader: Codable, Sendable {
    /// The algorithm used with the signing.
    package var alg: String?

    /// The Signature's Content Type.
    package var typ: String?

    /// The Payload's Content Type.
    var cty: String?

    /// Critical fields.
    var crit: [String]?

    /// The JWT key identifier.
    var kid: JWKIdentifier?

    /// The x5c certificate chain.
    package var x5c: [String]?
}
