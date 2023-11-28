/// The header (details) used for signing and processing the JWT.
public struct JWTHeader: Codable, Sendable {
    /// The algorithm used with the signing.
    package var alg: String?

    /// The Signature's Content Type.
    package var typ: String?

    /// The Payload's Content Type.
    var cty: String?

    /// The JWT key identifier.
    package var kid: JWKIdentifier?

    /// The x5c certificate chain.
    package var x5c: [String]?

    /// Custom fields.
    package var customFields: [String: JWTHeaderField]?
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
