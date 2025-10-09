#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

/// A protocol defining the requirements for payloads that include a validation time.
///
/// This protocol extends `JWTPayload` to include an additional `signedDate` property.
/// It is used to represent JWT payloads that require a date to validate the date the token was signed.
public protocol ValidationTimePayload: JWTPayload {
    var signedDate: Date { get }
}
