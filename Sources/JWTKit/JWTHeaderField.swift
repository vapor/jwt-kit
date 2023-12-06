import Foundation

public indirect enum JWTHeaderField: Hashable, Sendable, Codable {
    case null
    case bool(Bool)
    case int(Int)
    case decimal(Double)
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

        do { self = try .decimal(container.decode(Double.self)); return }
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
        case let .decimal(value): try container.encode(value)
        case let .string(value): try container.encode(value)
        case let .array(value): try container.encode(value)
        case let .object(value): try container.encode(value)
        }
    }
}

public extension JWTHeaderField {
    internal var isNull: Bool { if case .null = self { true } else { false } }
    var asBool: Bool? { get throws { if case let .bool(b) = self { b } else { throw JWTError.invalidHeaderField(reason: "Element is not a bool") } } }
    var asInt: Int? { get throws { if case let .int(i) = self { i } else { throw JWTError.invalidHeaderField(reason: "Element is not an int") } } }
    var asDecimal: Double? { get throws { if case let .decimal(d) = self { d } else { throw JWTError.invalidHeaderField(reason: "Element is not a decimal") } } }
    var asString: String? { get throws { if case let .string(s) = self { s } else { throw JWTError.invalidHeaderField(reason: "Element is not a string") } } }
    internal var asArray: [Self]? { get throws { if case let .array(a) = self { a } else { throw JWTError.invalidHeaderField(reason: "Element is not an array") } } }
    internal var asObject: [String: Self]? { get throws { if case let .object(o) = self { o } else { throw JWTError.invalidHeaderField(reason: "Element is not a JSON object") } } }
}

extension JWTHeaderField {
    var isBool: Bool { get throws { try self.asBool != nil } }
    var isInteger: Bool { get throws { try self.asInt != nil } }
    var isDecimal: Bool { get throws { try self.asDecimal != nil } }
    var isString: Bool { get throws { try self.asString != nil } }
}

public extension JWTHeaderField {
    func asObject<T>(of _: T.Type) throws -> [String: T] {
        guard let object = try self.asObject else {
            throw JWTError.invalidHeaderField(reason: "Element is not an object")
        }
        let values: [String: T]? = switch T.self {
        case is Bool.Type: try object.compactMapValues { try $0.asBool } as? [String: T]
        case is Int.Type: try object.compactMapValues { try $0.asInt } as? [String: T]
        case is Double.Type: try object.compactMapValues { try $0.asDecimal } as? [String: T]
        case is String.Type: try object.compactMapValues { try $0.asString } as? [String: T]
        default: nil
        }
        guard let values, object.count == values.count else {
            throw JWTError.invalidHeaderField(reason: "Object is not homogeneous")
        }
        return values
    }

    func asArray<T>(of _: T.Type) throws -> [T] {
        guard let array = try self.asArray else {
            throw JWTError.invalidHeaderField(reason: "Element is not an array")
        }
        let values: [T]? = switch T.self {
        case is Bool.Type: try array.compactMap { try $0.asBool } as? [T]
        case is Int.Type: try array.compactMap { try $0.asInt } as? [T]
        case is Double.Type: try array.compactMap { try $0.asDecimal } as? [T]
        case is String.Type: try array.compactMap { try $0.asString } as? [T]
        default: nil
        }
        guard let values, array.count == values.count else {
            throw JWTError.invalidHeaderField(reason: "Array is not homogeneous")
        }
        return values
    }
}

extension JWTHeaderField: ExpressibleByStringLiteral {
    public init(stringLiteral value: StringLiteralType) {
        self = .string(value)
    }
}

extension JWTHeaderField: ExpressibleByIntegerLiteral {
    public init(integerLiteral value: IntegerLiteralType) {
        self = .int(value)
    }
}

extension JWTHeaderField: ExpressibleByBooleanLiteral {
    public init(booleanLiteral value: BooleanLiteralType) {
        self = .bool(value)
    }
}

extension JWTHeaderField: ExpressibleByFloatLiteral {
    public init(floatLiteral value: FloatLiteralType) {
        self = .decimal(value)
    }
}

extension JWTHeaderField: ExpressibleByArrayLiteral {
    public init(arrayLiteral elements: JWTHeaderField...) {
        self = .array(elements)
    }
}

extension JWTHeaderField: ExpressibleByDictionaryLiteral {
    public init(dictionaryLiteral elements: (String, JWTHeaderField)...) {
        self = .object(Dictionary(uniqueKeysWithValues: elements))
    }
}
