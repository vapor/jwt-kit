#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

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

        do {
            container = try decoder.singleValueContainer()
        } catch DecodingError.typeMismatch {
            self = .null
            return
        }

        if container.decodeNil() {
            self = .null
            return
        }

        do {
            self = try .bool(container.decode(Bool.self))
            return
        } catch DecodingError.typeMismatch {}

        // This is a bit of a hack to correctly differentiate between integers and doubles
        do {
            let doubleValue = try container.decode(Double.self)
            if doubleValue.truncatingRemainder(dividingBy: 1) == 0 {
                self = .int(Int(doubleValue))
            } else {
                self = .decimal(doubleValue)
            }
            return
        } catch DecodingError.typeMismatch {}

        do {
            self = try .string(container.decode(String.self))
            return
        } catch DecodingError.typeMismatch {}

        do {
            self = try .array(container.decode([Self].self))
            return
        } catch DecodingError.typeMismatch {}

        do {
            self = try .object(container.decode([String: Self].self))
            return
        } catch DecodingError.typeMismatch {}

        throw DecodingError.dataCorruptedError(
            in: container, debugDescription: "No valid JSON type found.")
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.singleValueContainer()
        switch self {
        case .null: try container.encodeNil()
        case .bool(let value): try container.encode(value)
        case .int(let value): try container.encode(value)
        case .decimal(let value): try container.encode(value)
        case .string(let value): try container.encode(value)
        case .array(let value): try container.encode(value)
        case .object(let value): try container.encode(value)
        }
    }
}

extension JWTHeaderField {
    public var isNull: Bool { if case .null = self { true } else { false } }
    public var asBool: Bool? { if case .bool(let b) = self { b } else { nil } }
    public var asInt: Int? { if case .int(let i) = self { i } else { nil } }
    public var asDecimal: Double? { if case .decimal(let d) = self { d } else { nil } }
    public var asString: String? { if case .string(let s) = self { s } else { nil } }
    public var asArray: [Self]? { if case .array(let a) = self { a } else { nil } }
    public var asObject: [String: Self]? { if case .object(let o) = self { o } else { nil } }
}

extension JWTHeaderField {
    public func asObject<T>(of _: T.Type) throws -> [String: T] {
        guard let object = self.asObject else {
            throw JWTError.invalidHeaderField(reason: "Element is not an object")
        }
        let values: [String: T]? =
            switch T.self {
            case is Bool.Type: object.compactMapValues { $0.asBool } as? [String: T]
            case is Int.Type: object.compactMapValues { $0.asInt } as? [String: T]
            case is Double.Type: object.compactMapValues { $0.asDecimal } as? [String: T]
            case is String.Type: object.compactMapValues { $0.asString } as? [String: T]
            default: nil
            }
        guard let values, object.count == values.count else {
            throw JWTError.invalidHeaderField(reason: "Object is not homogeneous")
        }
        return values
    }

    public func asArray<T>(of _: T.Type) throws -> [T] {
        guard let array = self.asArray else {
            throw JWTError.invalidHeaderField(reason: "Element is not an array")
        }
        let values: [T]? =
            switch T.self {
            case is Bool.Type: array.compactMap { $0.asBool } as? [T]
            case is Int.Type: array.compactMap { $0.asInt } as? [T]
            case is Double.Type: array.compactMap { $0.asDecimal } as? [T]
            case is String.Type: array.compactMap { $0.asString } as? [T]
            default: nil
            }
        guard let values, array.count == values.count else {
            throw JWTError.invalidHeaderField(reason: "Array is not homogeneous")
        }
        return values
    }
}

extension JWTHeaderField: ExpressibleByNilLiteral {
    public init(nilLiteral _: ()) {
        self = .null
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
