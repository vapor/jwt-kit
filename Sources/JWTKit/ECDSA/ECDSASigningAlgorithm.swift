public protocol ECDSASigningAlgorithm {
    static var name: String { get }
    static var digestAlgorithm: DigestAlgorithm { get }
}
