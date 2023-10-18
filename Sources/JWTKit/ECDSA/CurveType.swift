public protocol CurveType {
    associatedtype Signature
    associatedtype PrivateKey: ECDSAPrivateKey
    static var curve: ECDSACurve { get }
}
