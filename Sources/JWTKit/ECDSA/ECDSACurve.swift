public struct ECDSACurve {
    let curve: String

    static var p256: Self {
        Self(curve: "P-256")
    }

    static var p384: Self {
        Self(curve: "P-384")
    }

    static var p521: Self {
        Self(curve: "P-521")
    }

    static var ed25519: Self {
        Self(curve: "Ed25519")
    }

    static var ed448: Self {
        Self(curve: "Ed448")
    }
}

extension ECDSACurve: Equatable {}
