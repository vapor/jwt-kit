/// The header (details) used for signing and processing the JWT.
@dynamicMemberLookup
public struct JWTHeader: Sendable {
    public var fields: [String: JWTHeaderField]

    public init(fields: [String: JWTHeaderField] = [:]) {
        self.fields = fields
    }

    public subscript(dynamicMember member: String) -> JWTHeaderField? {
        get { self.fields[member] }
        set {
            if let newValue = newValue {
                self.fields[member] = newValue
            } else {
                self.fields[member] = .null
            }
        }
    }

    public mutating func removeField(_ key: String) {
        self.fields.removeValue(forKey: key)
    }
}

extension JWTHeader: ExpressibleByDictionaryLiteral {
    public init(dictionaryLiteral elements: (String, JWTHeaderField)...) {
        self.init(fields: Dictionary(uniqueKeysWithValues: elements))
    }
}

extension JWTHeader: Codable {
    public func encode(to encoder: Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        try self.fields.forEach { key, value in
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
