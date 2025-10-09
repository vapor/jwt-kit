#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

/// The "iat" (issued at) claim identifies the time at which the JWT was
/// issued.  This claim can be used to determine the age of the JWT.  Its
/// value MUST be a number containing a NumericDate value.  Use of this
/// claim is OPTIONAL.
public struct IssuedAtClaim: JWTUnixEpochClaim, Equatable {
    /// See ``JWTClaim``.
    public var value: Date

    /// See ``JWTClaim``.
    public init(value: Date) {
        self.value = value
    }
}
