/// The header (details) used for signing and processing the JWT.
struct JWTHeader: Codable {
    /// The algorithm used with the signing.
    var alg: String?
    
    /// The Signature's Content Type.
    var typ: String?
    
    /// The Payload's Content Type.
    var cty: String?

    /// Critical fields.
    var crit: [String]?

    /// The JWT key identifier.
    var kid: JWKIdentifier?

    /// The x5c certificate chain.
    var x5c: [String]?
}

