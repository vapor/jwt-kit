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
public struct JWK: Codable, Equatable, Hashable, Sendable {
    /// The `kty` (key type) parameter identifies the cryptographic algorithm
    /// family used with the key, such as `RSA` or `ECDSA`.
    /// See [RFC 7517 Section 4.1](https://datatracker.ietf.org/doc/html/rfc7517#section-4.1)
    public var keyType: KeyType

    /// The `alg` (algorithm) parameter identifies the algorithm intended for
    /// use with the key. The `alg` value is a case-sensitive ASCII string.
    public var algorithm: Algorithm?

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

    /// `n` Modulus.
    ///
    /// Represented as the base64url encoding of the value's unsigned big endian representation as an octet sequence.
    public var modulus: String?

    /// `e` Exponent.
    public var exponent: String?

    /// `d` Private exponent: the private exponent of an RSA key, or the private key of an EC or OKP key.
    public var privateExponent: String?

    /// `p` First prime factor.
    public var prime1: String?

    /// `q` Second prime factor.
    public var prime2: String?

    /// `x` coordinate.
    public var x: String?

    /// `y` coordinate.
    public var y: String?

    /// `crv` curve.
    public var curve: Curve?

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
            keyType: .rsa,
            algorithm: algorithm,
            keyIdentifier: identifier,
            modulus: modulus,
            exponent: exponent,
            privateExponent: privateExponent
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
            keyType: .ecdsa,
            algorithm: algorithm,
            keyIdentifier: identifier,
            privateExponent: privateKey,
            x: x,
            y: y,
            curve: curve.map { .ecdsa($0) }
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
            keyType: .octetKeyPair,
            algorithm: algorithm,
            keyIdentifier: identifier,
            privateExponent: privateKey,
            x: x,
            curve: curve.map { .eddsa($0) }
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
        .octetKeyPair(algorithm, identifier: identifier, x: x, curve: curve, privateKey: privateKey)
    }

    private init(
        keyType: KeyType,
        algorithm: Algorithm? = nil,
        keyIdentifier: JWKIdentifier? = nil,
        modulus: String? = nil,
        exponent: String? = nil,
        privateExponent: String? = nil,
        prime1: String? = nil,
        prime2: String? = nil,
        x: String? = nil,
        y: String? = nil,
        curve: Curve? = nil
    ) {
        self.keyType = keyType
        self.algorithm = algorithm
        self.keyIdentifier = keyIdentifier
        self.modulus = modulus
        self.exponent = exponent
        self.privateExponent = privateExponent
        self.prime1 = prime1
        self.prime2 = prime2
        self.x = x
        self.y = y
        self.curve = curve
    }
}
