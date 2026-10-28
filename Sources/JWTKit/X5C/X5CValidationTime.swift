#if !canImport(Darwin)
public import FoundationEssentials
#else
public import Foundation
#endif

/// The point in time at which an ``X5CVerifier`` validates the `x5c` certificate chain of a JWS.
///
/// Use ``currentTime`` unless you need to accept tokens signed in the past,
/// and prefer ``signedDate(maxAge:)`` to bound how far back validation can be moved.
public struct X5CValidationTime: Sendable {
    enum Backing: Sendable {
        case currentTime
        case signedDate(maxAge: TimeInterval?)
        case fixed(Date)
    }

    let backing: Backing

    /// Validate the certificate chain against the current time, ignoring any `signedDate` in the payload.
    ///
    /// This is the default.
    public static let currentTime = Self(backing: .currentTime)

    /// Validate the certificate chain against the payload's `signedDate` if the payload conforms
    /// to ``ValidationTimePayload``, falling back to the current time otherwise.
    ///
    /// This allows verifying tokens whose signing certificate has expired since the token was
    /// signed, at the cost of letting the token itself choose the validation time. Prefer
    /// ``signedDate(maxAge:)`` to bound how far into the past that choice can reach.
    public static let signedDate = Self(backing: .signedDate(maxAge: nil))

    /// Like ``signedDate``, but rejects tokens whose `signedDate` lies more than `maxAge` seconds
    /// in the past, limiting how far an attacker can backdate certificate validation.
    ///
    /// `maxAge` bounds the past only; a `signedDate` in the future is rejected by both
    /// ``signedDate`` and this variant.
    public static func signedDate(maxAge: TimeInterval) -> Self {
        Self(backing: .signedDate(maxAge: maxAge))
    }

    /// Validate the certificate chain against a fixed, caller-provided date.
    public static func fixed(_ date: Date) -> Self {
        Self(backing: .fixed(date))
    }
}
