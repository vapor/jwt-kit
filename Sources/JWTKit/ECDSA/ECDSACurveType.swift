/// A protocol defining the requirements for elliptic curve types used in ECDSA (Elliptic Curve Digital Signature Algorithm).
///
/// This protocol specifies the necessary components and characteristics for an elliptic curve to be used in ECDSA.
/// Implementations of this protocol should provide specific types and values associated with a particular elliptic curve,
/// allowing for a more generic handling of ECDSA operations across different curves.
///
/// Types conforming to this protocol are used to define the characteristics of specific elliptic curves,
/// such as the curve used (represented by ``ECDSACurve``), and the byte ranges for the x and y coordinates
/// that are crucial in elliptic curve cryptography.
///
/// Conformance to this protocol requires specifying:
/// - ``Signature``: The type representing a signature produced using the ECDSA algorithm with the specific curve.
/// - ``PrivateKey``: The type representing a private key compatible with the specific curve. It must conform to ``ECDSAPrivateKey``.
/// - ``curve``: A static property providing the ``ECDSACurve`` instance associated with the specific curve.
/// - ``byteRanges``: A static property specifying the byte ranges for the x and y coordinates on the curve.
///
/// Types conforming to this protocol can be used to abstract ECDSA cryptographic operations across various elliptic curves,
/// allowing for flexible and modular cryptographic code.
public protocol ECDSACurveType: Sendable {
    associatedtype Signature: ECDSASignature
    associatedtype PrivateKey: ECDSAPrivateKey
    associatedtype SigningAlgorithm: ECDSASigningAlgorithm

    static var curve: ECDSACurve { get }
    static var byteRanges: (x: Range<Int>, y: Range<Int>) { get }
}
