#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

/// A JSON Web Key.
///
/// A JSON Web Key (JWK) is a JavaScript Object Notation (JSON) data
/// structure that represents a cryptographic key.
///
/// See more at [RFC 7517](https://tools.ietf.org/html/rfc7517).
public struct JWK: Codable, Sendable {
    /// The key material. Everything inside JWTKit works from this rather than the flat members.
    var parameters: Parameters

    /// The `kid` (key ID) parameter is used to match a specific key. This is
    /// used, for instance, to choose among a set of keys within a JWK Set
    /// during key rollover.
    ///
    /// The structure of the `kid` value is unspecified. When `kid` values
    /// are used within a JWK Set, different keys within the JWK set should
    /// use distinct `kid` values.
    ///
    /// The `kid` value is a case-sensitive string.
    public var keyIdentifier: JWKIdentifier?

    /// The `alg` (algorithm) parameter identifies the algorithm intended for
    /// use with the key. The `alg` value is a case-sensitive ASCII string.
    public var algorithm: Algorithm?

    /// The `kty` (key type) parameter identifies the cryptographic algorithm
    /// family used with the key, such as `RSA` or `ECDSA`.
    /// See [RFC 7515 Section 4.1](https://datatracker.ietf.org/doc/html/rfc7517#section-4.1)
    public var keyType: KeyType {
        get { self.parameters.members.keyType }
        set { self.updateMembers { $0.keyType = newValue } }
    }

    /// `n` Modulus.
    ///
    /// Represented as the base64url encoding of the value's unsigned big endian representation as an octet sequence.
    ///
    /// Carried by RSA keys: on a complete key of another type it reads as `nil` and setting it is discarded.
    public var modulus: String? {
        get { self.parameters.members.modulus }
        set { self.updateMembers { $0.modulus = newValue } }
    }

    /// `e` Exponent.
    ///
    /// Carried by RSA keys: on a complete key of another type it reads as `nil` and setting it is discarded.
    public var exponent: String? {
        get { self.parameters.members.exponent }
        set { self.updateMembers { $0.exponent = newValue } }
    }

    /// `d` Private exponent.
    ///
    /// Carried by every key type: the private exponent of an RSA key, or the private key of an EC or OKP key.
    public var privateExponent: String? {
        get { self.parameters.members.privateExponent }
        set { self.updateMembers { $0.privateExponent = newValue } }
    }

    /// `p` First prime factor.
    ///
    /// Carried by RSA keys: on a complete key of another type it reads as `nil` and setting it is discarded.
    public var prime1: String? {
        get { self.parameters.members.prime1 }
        set { self.updateMembers { $0.prime1 = newValue } }
    }

    /// `q` Second prime factor.
    ///
    /// Carried by RSA keys: on a complete key of another type it reads as `nil` and setting it is discarded.
    public var prime2: String? {
        get { self.parameters.members.prime2 }
        set { self.updateMembers { $0.prime2 = newValue } }
    }

    /// `x` coordinate.
    ///
    /// Carried by EC and OKP keys: on a complete key of another type it reads as `nil` and setting it is discarded.
    public var x: String? {
        get { self.parameters.members.x }
        set { self.updateMembers { $0.x = newValue } }
    }

    /// `y` coordinate.
    ///
    /// Carried by EC keys: on a complete key of another type it reads as `nil` and setting it is discarded.
    public var y: String? {
        get { self.parameters.members.y }
        set { self.updateMembers { $0.y = newValue } }
    }

    /// `crv` curve.
    ///
    /// Carried by EC and OKP keys: on a complete key of another type it reads as `nil` and setting it is discarded.
    public var curve: Curve? {
        get { self.parameters.members.curve }
        set { self.updateMembers { $0.curve = newValue } }
    }

    private mutating func updateMembers(_ body: (inout Members) -> Void) {
        var members = self.parameters.members
        body(&members)
        self.parameters = members.normalized()
    }

    init(parameters: Parameters, algorithm: Algorithm? = nil, keyIdentifier: JWKIdentifier? = nil) {
        self.parameters = parameters
        self.algorithm = algorithm
        self.keyIdentifier = keyIdentifier
    }

    public init(json: String) throws {
        self = try JSONDecoder().decode(JWK.self, from: Data(json.utf8))
    }

    public static func rsa(
        _ algorithm: Algorithm?,
        identifier: JWKIdentifier?,
        modulus: String?,
        exponent: String?,
        privateExponent: String? = nil
    ) -> JWK {
        .init(
            parameters: Members(
                keyType: .rsa,
                modulus: modulus,
                exponent: exponent,
                privateExponent: privateExponent
            ).normalized(),
            algorithm: algorithm,
            keyIdentifier: identifier
        )
    }

    public static func ecdsa(
        _ algorithm: Algorithm?,
        identifier: JWKIdentifier?,
        x: String?,
        y: String?,
        curve: ECDSACurve?,
        privateKey: String? = nil
    ) -> JWK {
        .init(
            parameters: Members(
                keyType: .ecdsa,
                privateExponent: privateKey,
                x: x,
                y: y,
                curve: curve.map { .ecdsa($0) }
            ).normalized(),
            algorithm: algorithm,
            keyIdentifier: identifier
        )
    }

    public static func octetKeyPair(
        _ algorithm: Algorithm?,
        identifier: JWKIdentifier?,
        x: String?,
        curve: EdDSACurve?,
        privateKey: String? = nil
    ) -> JWK {
        .init(
            parameters: Members(
                keyType: .octetKeyPair,
                privateExponent: privateKey,
                x: x,
                curve: curve.map { .eddsa($0) }
            ).normalized(),
            algorithm: algorithm,
            keyIdentifier: identifier
        )
    }

    /// - Note: The `y` parameter is unused: an octet key pair has no `y` coordinate. This overload
    ///   exists only so that call sites written against `JWK` keep compiling, and is deprecated in
    ///   favour of the one above.
    @available(*, deprecated, renamed: "octetKeyPair(_:identifier:x:curve:privateKey:)")
    public static func octetKeyPair(
        _ algorithm: Algorithm?,
        identifier: JWKIdentifier?,
        x: String?,
        y _: String?,
        curve: EdDSACurve?,
        privateKey: String? = nil
    ) -> JWK {
        .init(
            parameters: Members(
                keyType: .octetKeyPair,
                privateExponent: privateKey,
                x: x,
                curve: curve.map { .eddsa($0) }
            ).normalized(),
            algorithm: algorithm,
            keyIdentifier: identifier
        )
    }

    private enum CodingKeys: String, CodingKey {
        case keyType = "kty"
        case algorithm = "alg"
        case keyIdentifier = "kid"
        case modulus = "n"
        case exponent = "e"
        case privateExponent = "d"
        case prime1 = "p"
        case prime2 = "q"
        case curve = "crv"
        case x
        case y
    }

    public init(from decoder: any Decoder) throws {
        let container = try decoder.container(keyedBy: CodingKeys.self)

        self.keyIdentifier = try container.decodeIfPresent(JWKIdentifier.self, forKey: .keyIdentifier)
        self.algorithm = try container.decodeIfPresent(Algorithm.self, forKey: .algorithm)
        self.parameters = try Members(
            keyType: container.decode(KeyType.self, forKey: .keyType),
            modulus: container.decodeIfPresent(String.self, forKey: .modulus),
            exponent: container.decodeIfPresent(String.self, forKey: .exponent),
            privateExponent: container.decodeIfPresent(String.self, forKey: .privateExponent),
            prime1: container.decodeIfPresent(String.self, forKey: .prime1),
            prime2: container.decodeIfPresent(String.self, forKey: .prime2),
            x: container.decodeIfPresent(String.self, forKey: .x),
            y: container.decodeIfPresent(String.self, forKey: .y),
            curve: container.decodeIfPresent(Curve.self, forKey: .curve)
        ).normalized()
    }

    public func encode(to encoder: any Encoder) throws {
        var container = encoder.container(keyedBy: CodingKeys.self)
        let members = self.parameters.members

        try container.encode(members.keyType, forKey: .keyType)
        try container.encodeIfPresent(self.algorithm, forKey: .algorithm)
        try container.encodeIfPresent(self.keyIdentifier, forKey: .keyIdentifier)
        try container.encodeIfPresent(members.modulus, forKey: .modulus)
        try container.encodeIfPresent(members.exponent, forKey: .exponent)
        try container.encodeIfPresent(members.privateExponent, forKey: .privateExponent)
        try container.encodeIfPresent(members.prime1, forKey: .prime1)
        try container.encodeIfPresent(members.prime2, forKey: .prime2)
        try container.encodeIfPresent(members.x, forKey: .x)
        try container.encodeIfPresent(members.y, forKey: .y)
        try container.encodeIfPresent(members.curve, forKey: .curve)
    }
}
