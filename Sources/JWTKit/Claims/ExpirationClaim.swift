#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

/// The "exp" (expiration time) claim identifies the expiration time on
/// or after which the JWT MUST NOT be accepted for processing.  The
/// processing of the "exp" claim requires that the current date/time
/// MUST be before the expiration date/time listed in the "exp" claim.
/// Implementers MAY provide for some small leeway, usually no more than
/// a few minutes, to account for clock skew.  Its value MUST be a number
/// containing a NumericDate value.  Use of this claim is OPTIONAL.
public struct ExpirationClaim: JWTUnixEpochClaim, Equatable {
    /// See ``JWTClaim``.
    public var value: Date

    /// See ``JWTClaim``.
    public init(value: Date) {
        self.value = value
    }

    /// Throws an error if the claim's date is later than current date.
    public func verifyNotExpired(currentDate: Date = .init()) throws {
        switch self.value.compare(currentDate) {
        case .orderedAscending, .orderedSame:
            throw JWTError.claimVerificationFailure(failedClaim: self, reason: "expired")
        case .orderedDescending:
            break
        }
    }
}
