public struct TenantIDClaim: JWTClaim, Equatable {
    /// See ``JWTClaim``.
    public var value: String?

    /// See ``JWTClaim``.
    public init(value: String?) {
        self.value = value
    }
}
