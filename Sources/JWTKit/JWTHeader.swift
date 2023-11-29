/// The header (details) used for signing and processing the JWT.
public struct JWTHeader: Codable, Sendable {
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
    public var customFields: [String: JWTHeaderField]?

    init() {}

    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try container.encodeIfPresent(self.alg, forKey: .alg)
        try container.encodeIfPresent(self.typ, forKey: .typ)
        try container.encodeIfPresent(self.cty, forKey: .cty)
        try container.encodeIfPresent(self.kid, forKey: .kid)
        try container.encodeIfPresent(self.x5c, forKey: .x5c)

        if let customFields = self.customFields {
            try customFields.forEach { key, value in
                try container.encode(value, forKey: .custom(name: key))
            }
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)
        self.alg = try container.decodeIfPresent(String.self, forKey: .alg)
        self.typ = try container.decodeIfPresent(String.self, forKey: .typ)
        self.cty = try container.decodeIfPresent(String.self, forKey: .cty)
        self.kid = try container.decodeIfPresent(JWKIdentifier.self, forKey: .kid)
        self.x5c = try container.decodeIfPresent([String].self, forKey: .x5c)

        let excludedKeys: Set<String> = ["alg", "typ", "cty", "kid", "x5c"]

        self.customFields = try container.allKeys
            .filter { !excludedKeys.contains($0.stringValue) }
            .reduce(into: [String: JWTHeaderField]()) { result, key in
                result[key.stringValue] = try container.decode(JWTHeaderField.self, forKey: key)
            }
    }

    private enum CodingKeys: CodingKey {
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

        init?(stringValue: String) {
            self = .custom(name: stringValue)
        }

        var intValue: Int? { nil }
        init?(intValue _: Int) { nil }

        case alg
        case typ
        case cty
        case kid
        case x5c
        case custom(name: String)
    }
}

public indirect enum JWTHeaderField: Hashable, Sendable, Codable {
    case null
    case bool(Bool)
    case int(Int)
    case string(String)
    case array([JWTHeaderField])
    case object([String: JWTHeaderField])

    public init(from decoder: any Decoder) throws {
        let container: any SingleValueDecodingContainer
        do { container = try decoder.singleValueContainer() }
        catch DecodingError.typeMismatch { self = .null; return }
        if container.decodeNil() { self = .null; return }

        do { self = try .bool(container.decode(Bool.self)); return }
        catch DecodingError.typeMismatch {}

        do { self = try .int(container.decode(Int.self)); return }
        catch DecodingError.typeMismatch {}

        do { self = try .string(container.decode(String.self)); return }
        catch DecodingError.typeMismatch {}

        do { self = try .array(container.decode([Self].self)); return }
        catch DecodingError.typeMismatch {}

        do { self = try .object(container.decode([String: Self].self)); return }
        catch DecodingError.typeMismatch {}

        throw DecodingError.dataCorruptedError(in: container, debugDescription: "No valid JSON type found.")
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: break
        case let .bool(value): try container.encode(value)
        case let .int(value): try container.encode(value)
        case let .string(value): try container.encode(value)
        case let .array(value): try container.encode(value)
        case let .object(value): try container.encode(value)
        }
    }
}
