public protocol ECDSACurveType {
    associatedtype Signature
    associatedtype PrivateKey: ECDSAPrivateKey
    static var curve: ECDSACurve { get }
    static var byteRanges: (x: Range<Int>, y: Range<Int>) { get }
}
