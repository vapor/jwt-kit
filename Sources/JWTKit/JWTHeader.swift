/// The header (details) used for signing and processing the JWT.
@dynamicMemberLookup
public struct JWTHeader: Sendable {
    public var fields: [String: JWTHeaderField]

    public init(fields: [String: JWTHeaderField] = [:]) {
        self.fields = fields
    }

    subscript(dynamicMember member: String) -> JWTHeaderField? {
        get { fields[member] }
        set { fields[member] = newValue }
    }
}

extension JWTHeader: Codable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try fields.forEach { key, value in
            try container.encode(value, forKey: .custom(name: key))
        }
    }

    public init(from decoder: Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.fields = try Set(container.allKeys)
            .reduce(into: [String: JWTHeaderField]()) { result, key in
                result[key.stringValue] = try container.decode(JWTHeaderField.self, forKey: key)
            }
    }

    private enum CodingKeys: CodingKey, Equatable, Hashable {
        case custom(name: String)

        var stringValue: String {
            switch self {
            case let .custom(name):
                return name
            }
        }

        var intValue: Int? { nil }

        init?(stringValue: String) {
            self = .custom(name: stringValue)
        }

        init?(intValue _: Int) { nil }
    }
}
