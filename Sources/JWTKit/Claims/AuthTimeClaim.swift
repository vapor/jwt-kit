#if !canImport(Darwin)
    import FoundationEssentials
#else
    import Foundation
#endif

/// The "auth_time" (authentication time) claim identifies the time at which
/// the user authentication occurred. Its value is a JSON number representing
/// the number of seconds from 1970-01-01T00:00:00Z as measured in UTC until
/// the date/time. When used in an ID Token, it MUST be the time at which the
/// user authentication occurred, regardless of whether that was via a classic
/// login or via a single sign-on protocol. The authentication time value
/// can be used to determine the age of the user's authentication event.
public struct AuthTimeClaim: JWTClaim, Equatable {
    /// See ``JWTClaim``.
    public var value: Date
    
    /// See ``JWTClaim``.
    public init(value: Date) {
        self.value = value
    }
    
    /// Verifies that the authentication time is within the specified time interval
    /// from the current time.
    ///
    /// - Parameter timeInterval: The maximum allowed time interval between the authentication time and the current time.
    /// - Throws: ``JWTError/claimVerificationFailure`` if the authentication time is outside the acceptable time window.
    public func verifyAuthTime(within timeInterval: TimeInterval) throws {
        let now = Date()
        guard abs(value.timeIntervalSince(now)) <= timeInterval else {
            throw JWTError.claimVerificationFailure(
                failedClaim: self,
                reason: "Auth time '\(value)' is outside acceptable time window"
            )
        }
    }
}
