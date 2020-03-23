import Foundation

public protocol JWTMultiValueClaim: JWTClaim where Value: Collection, Value.Element: Codable {
    init(value: Value.Element)
}

extension JWTMultiValueClaim {
    
    /// Single-element initializer. Uses the `CollectionOfOneDecoder` to work
    /// around the lack of an initializer on the `Collection` protocol. Not
    /// spectacularly efficient, but it works.
    public init(value: Value.Element) {
        self.init(value: try! CollectionOfOneDecoder<Value>.decode(value))
    }

    /// Because multi-value claims can take either singular or plural form in
    /// JSON, the default conformance to `Decodable` from `JWTClaim` isn't good
    /// enough.
    ///
    /// - Note: The spec is mute on what multi-value claims like `aud` with an
    ///   empty list of values would be considered to represent - whether it
    ///   would be the same as having no claim at all, or represent a token
    ///   making the claim but with zero values. For maximal flexibility, this
    ///   implementation accepts an empty unkeyed container (in JSON, `[]`)
    ///   silently.
    ///
    /// - Note: It would be preferable to be able to safely decode the empty
    ///   array from a lack of _any_ encoded value. This is precluded by the way
    ///   `Codable` works, as either the claim would have to be marked
    ///   optional in the payload, leading to the ambiguity of having both `nil`
    ///   and `[]` representations, each payload type would have to manually
    ///   implement `init(from decoder:)` to use `decodeIfPresent(_:forKey:)`
    ///   and a fallback value, or we would have to export extensions on
    ///   `KeyedEncodingContainer` and `KeyedEncodingContainerProtocol` to
    ///   explicitly override behavior for types confroming to
    ///   `JWTMultiValueClaim`, a tricky and error-prone approach relying on
    ///   poorly-understood mechanics of static versus dynamic dispatch.
    ///
    /// - Note: The spec is also mute regarding the behavior of duplicate values
    ///   in a list of more than one. This implementation behaves according to
    ///   the semantics of the particular `Collection` type used as its value;
    ///   `Array` will preserve ordering and duplicates, `Set` will not.
    public init(from decoder: Decoder) throws {
        let container = try decoder.singleValueContainer()

        do {
            self.init(value: try container.decode(Value.Element.self))
        } catch DecodingError.typeMismatch(let type, let context)
                where type == Value.Element.self && context.codingPath.count == container.codingPath.count {
            // Unfortunately, `typeMismatch()` doesn't let us explicitly look for what type found,
            // only what type was expected, so we have to match the coding path depth instead.
            self.init(value: try container.decode(Value.self))
        }
    }

    /// This claim can take either singular or plural form in JSON, with the
    /// singular being overwhelmingly more common, so when there is only one
    /// value, ensure it is encoded as a scalar, not an array.
    ///
    /// - Note: As in decoding, the implementation takes a conservative approach
    ///   with regards to the importance of ordering and the handling of
    ///   duplicate values by simply encoding what's there without further
    ///   analysis or filtering.
    ///
    /// - Warning: If the claim has zero values, this implementation will encode
    ///   an inefficient zero-element representation. See the notes regarding
    ///   this on `init(from decoder:)` above.
    public func encode(to encoder: Encoder) throws {
        var container = encoder.singleValueContainer()
        
        switch self.value.first {
            case let .some(value) where self.value.count == 1:
                try container.encode(value)
            default:
                try container.encode(self.value)
        }
    }

}

/// A very quick-and-dirty `AnyOptionalType` to trivially`answer "is it nil"`
private protocol AnyOptionalType { var isNil: Bool { get } }
extension Optional: AnyOptionalType { var isNil: Bool { if case .none = self { return true } else { return false } } }

/// An extremely specialized `Decoder` whose only purpose is to spoon-feed the
/// type being decoded a single unkeyed element. This ridiculously intricate
/// workaround is used to get around the problem of `Collection` not having any
/// initializers for the single-value initializer of `JWTMultiValueClaim`. The
/// other workaround would be to require conformance to
/// `ExpressibleByArrayLiteral`, but what fun would that be?
private struct CollectionOfOneDecoder<T>: Decoder, UnkeyedDecodingContainer where T: Collection, T: Codable, T.Element: Codable {
    static func decode(_ element: T.Element) throws -> T { return try T.init(from: self.init(value: element)) }
    var value: T.Element
    var codingPath: [CodingKey] = [], userInfo: [CodingUserInfoKey : Any] = [:]
    var count: Int? = 1, currentIndex: Int = 0
    var isAtEnd: Bool { currentIndex != 0 }
    func container<Key>(keyedBy: Key.Type) throws -> KeyedDecodingContainer<Key> where Key : CodingKey { fatalError() }
    func singleValueContainer() throws -> SingleValueDecodingContainer { fatalError() }
    func unkeyedContainer() throws -> UnkeyedDecodingContainer { self }
    mutating func nestedContainer<N>(keyedBy: N.Type) throws -> KeyedDecodingContainer<N> where N: CodingKey { fatalError() }
    mutating func nestedUnkeyedContainer() throws -> UnkeyedDecodingContainer { fatalError() }
    mutating func superDecoder() throws -> Decoder { fatalError() }
    mutating func decodeNil() throws -> Bool {
        if let value = value as? AnyOptionalType, value.isNil { self.currentIndex += 1; return true }
        return false
    }
    mutating func decode<U>(_: U.Type) throws -> U where U : Decodable {
        guard U.self == T.Element.self else { throw DecodingError.typeMismatch(U.self, .init(codingPath: [], debugDescription: "")) }
        self.currentIndex += 1
        return value as! U
    }
}
