/// The header (details) used for signing and processing the JWT.
public struct JWTHeader: Sendable {
    /// The algorithm used with the signing.
    public var alg: String?

    /// The Signature's Content Type.
    public var typ: String?

    /// The Payload's Content Type.
    public var cty: String?

    /// The JWT key identifier.
    public var kid: JWKIdentifier?

    /// The x5c certificate chain.
    public var x5c: [String]?

    /// Custom fields.
    public var customFields: [String: JWTHeaderField]

    init(
        alg: String? = nil,
        typ: String? = nil,
        cty: String? = nil,
        kid: JWKIdentifier? = nil,
        x5c: [String]? = nil,
        customFields: [String: JWTHeaderField] = [:]
    ) {
        self.alg = alg
        self.typ = typ
        self.cty = cty
        self.kid = kid
        self.x5c = x5c
        self.customFields = customFields
    }
}

extension JWTHeader: Codable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(self.alg, forKey: .alg)
        try container.encodeIfPresent(self.typ, forKey: .typ)
        try container.encodeIfPresent(self.cty, forKey: .cty)
        try container.encodeIfPresent(self.kid, forKey: .kid)
        try container.encodeIfPresent(self.x5c, forKey: .x5c)
        try customFields.forEach { key, value in
            try container.encode(value, forKey: .custom(name: key))
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.alg = try container.decodeIfPresent(String.self, forKey: .alg)
        self.typ = try container.decodeIfPresent(String.self, forKey: .typ)
        self.cty = try container.decodeIfPresent(String.self, forKey: .cty)
        self.kid = try container.decodeIfPresent(JWKIdentifier.self, forKey: .kid)
        self.x5c = try container.decodeIfPresent([String].self, forKey: .x5c)

        self.customFields = try Set(container.allKeys)
            .subtracting(CodingKeys.allKeys)
            .reduce(into: [String: JWTHeaderField]()) { result, key in
                result[key.stringValue] = try container.decode(JWTHeaderField.self, forKey: key)
            }
    }

    private enum CodingKeys: CodingKey, Equatable, Hashable {
        case alg
        case typ
        case cty
        case kid
        case x5c
        case custom(name: String)

        static var allKeys: Set<CodingKeys> {
            [.alg, .typ, .cty, .kid, .x5c]
        }

        var stringValue: String {
            switch self {
            case .alg: "alg"
            case .typ: "typ"
            case .cty: "cty"
            case .kid: "kid"
            case .x5c: "x5c"
            case let .custom(name: name): name
            }
        }

        var intValue: Int? { nil }

        init?(stringValue: String) {
            switch stringValue {
            case "alg": self = .alg
            case "typ": self = .typ
            case "cty": self = .cty
            case "kid": self = .kid
            case "x5c": self = .x5c
            default: self = .custom(name: stringValue)
            }
        }

        init?(intValue _: Int) { nil }
    }
}
