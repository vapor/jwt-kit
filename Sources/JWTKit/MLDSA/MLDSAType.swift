public import Crypto

/// An MLDSA parameter set, which determines the strength of the keys and signatures it produces.
///
/// JWTKit supports the two parameter sets vended by SwiftCrypto: `MLDSA65` and `MLDSA87`. Each one
/// maps to the JWS algorithm of the same name registered by
/// [RFC 9964](https://datatracker.ietf.org/doc/rfc9964/).
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public protocol MLDSAType {
    /// The type of the private key belonging to this parameter set.
    associatedtype PrivateKey: MLDSAPrivateKey

    /// The name of the JWS algorithm this parameter set corresponds to, used as the `alg` header field
    /// of the tokens it signs.
    static var name: String { get }
}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA65: MLDSAType {
    /// The name of the JWS algorithm this parameter set corresponds to.
    public static var name: String { "ML-DSA-65" }
}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA87: MLDSAType {
    /// The name of the JWS algorithm this parameter set corresponds to.
    public static var name: String { "ML-DSA-87" }
}
