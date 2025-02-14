#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

/// The "nbf" (not before) claim identifies the time before which the JWT
/// MUST NOT be accepted for processing. The processing of the "nbf"
/// claim requires that the current date/time MUST be after or equal to
/// the not-before date/time listed in the "nbf" claim. Implementers MAY
/// provide for some small leeway, usually no more than a few minutes, to
/// account for clock skew. Its value MUST be a number containing a
/// NumericDate value. Use of this claim is OPTIONAL.
public struct NotBeforeClaim: JWTUnixEpochClaim, Equatable {
    /// See ``JWTClaim``.
    public var value: Date

    /// See ``JWTClaim``.
    public init(value: Date) {
        self.value = value
    }

    /// Throws an error if the claim's date is earlier than current date.
    public func verifyNotBefore(currentDate: Date = .init()) throws {
        switch value.compare(currentDate) {
        case .orderedDescending:
            throw JWTError.claimVerificationFailure(failedClaim: self, reason: "too soon")
        case .orderedAscending, .orderedSame:
            break
        }
    }
}
