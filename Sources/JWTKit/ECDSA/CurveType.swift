public protocol CurveType {
    associatedtype Signature
    associatedtype PrivateKey: ECDSAPrivateKey
    static var curve: ECDSACurve { get }
    static var byteRanges: (first: Range<Int>, second: Range<Int>) { get }
}
