
import X509
import SwiftASN1

/// This Policy acts as a placeholder. Its result is always positive.
public struct EmptyPolicy: VerifierPolicy {
    @inlinable
    public var verifyingCriticalExtensions: [SwiftASN1.ASN1ObjectIdentifier] { [] }

    @inlinable
    init() {}

    @inlinable
    public func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult { .meetsPolicy }
}
