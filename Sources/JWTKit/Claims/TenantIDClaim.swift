/// The "tid" (tenant ID) claim represents the unique identifier of the Azure AD tenant
/// that the token was issued by. This claim is present in tokens when a user signs in to an
/// application through Azure Active Directory. The tenant ID is a key piece of information
/// for identifying the tenant realm and is essential for applications that are multi-tenant aware.
/// The tenant ID is a GUID that is immutable and uniquely identifies an Azure AD tenant. This
/// claim is crucial for applications that need to enforce tenant-specific access control, and for
/// logging or auditing the tenant context of the authenticated user. The value of "tid" is a
/// case-sensitive string representing a GUID. The presence of this claim and its proper validation
/// are critical for the security of multi-tenant applications.
public struct TenantIDClaim: JWTClaim, Equatable, ExpressibleByStringLiteral, ExpressibleByNilLiteral {
    // See `JWTClaim.value`.
    public var value: String?

    // See `JWTClaim.init(value:)`.
    public init(value: String?) {
        self.value = value
    }

    public init(stringLiteral value: String) {
        self.init(value: value)
    }

    public init(nilLiteral: ()) {
        self.init(value: nil)
    }
}
