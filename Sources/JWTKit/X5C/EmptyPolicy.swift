//
//  AlwaysMeetsPolicy.swift
//  jwt-kit
//
//  Created by Bastian Rössler on 02.07.25.
//

import X509
import SwiftASN1

/// This Policy acts as a placeholder. Its result is always positive.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct EmptyPolicy: VerifierPolicy {
    @inlinable
    public var verifyingCriticalExtensions: [SwiftASN1.ASN1ObjectIdentifier] { [] }

    @inlinable
    init() {}

    @inlinable
    public func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        return .meetsPolicy
    }
}
