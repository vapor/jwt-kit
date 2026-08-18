extension JWK {
    /// The `crv` (curve) parameter identifies the cryptographic curve used with the key.
    /// Unknown curves are preserved.
    public struct Curve: Codable, RawRepresentable, Equatable, Sendable {
        enum Backing: Codable, Sendable {
            case ecdsa(ECDSACurve)
            case eddsa(EdDSACurve)
            case unknown(String)
        }

        let backing: Backing

        public var rawValue: String {
            switch self.backing {
            case .ecdsa(let ecdsaCurve):
                ecdsaCurve.rawValue
            case .eddsa(let eddsaCurve):
                eddsaCurve.rawValue
            case .unknown(let name):
                name
            }
        }

        /// Represents an ECDSA curve.
        public static func ecdsa(_ curve: ECDSACurve) -> Self { .init(.ecdsa(curve)) }

        /// Represents an EdDSA curve.
        public static func eddsa(_ curve: EdDSACurve) -> Self { .init(.eddsa(curve)) }

        /// Represents a curve JWTKit doesn't recognise, preserving its name.
        public static func unknown(_ rawValue: String) -> Self { .init(.unknown(rawValue)) }

        init(_ backing: Backing) {
            self.backing = backing
        }

        /// Creates a curve from its rawValue, falling back to `unknown` if it's not recognised.
        ///
        /// > Warning: This initialiser is failable due to source compatibility,
        /// > but it doesn't actually ever return `nil`. This should be fixed in the next major.
        public init?(rawValue: String) {
            if let ecdsaCurve = ECDSACurve(rawValue: rawValue) {
                self.init(.ecdsa(ecdsaCurve))
            } else if let eddsaCurve = EdDSACurve(rawValue: rawValue) {
                self.init(.eddsa(eddsaCurve))
            } else {
                self.init(.unknown(rawValue))
            }
        }

        public init(from decoder: any Decoder) throws {
            let rawValue = try decoder.singleValueContainer().decode(String.self)
            self = Self(rawValue: rawValue) ?? .unknown(rawValue)
        }

        public func encode(to encoder: any Encoder) throws {
            var container = encoder.singleValueContainer()
            try container.encode(self.rawValue)
        }
    }
}
