/// A provider-issued identity token whose audience must be bound to the
/// application that is accepting it.
///
/// Use ``JWTKeyCollection/verify(_:as:expectedAudience:trustedAdditionalAudiences:iteratingKeys:)``
/// or ``JWTKeyCollection/verify(_:as:expectedAudiences:trustedAdditionalAudiences:iteratingKeys:)``
/// to verify an identity token. Signature, issuer, and expiry checks alone do
/// not establish that a token was issued for your application.
public protocol JWTIdentityToken: JWTPayload {
    var audience: AudienceClaim { get }
}

struct JWTIdentityTokenValidation: Sendable {
    let expectedAudiences: Set<String>
    let trustedAdditionalAudiences: Set<String>
    let trustedAuthorizedPresenters: Set<String>?

    func validate(_ token: any JWTIdentityToken) throws {
        guard !self.expectedAudiences.isEmpty, !self.expectedAudiences.contains("") else {
            throw JWTError.generic(identifier: "Audience", reason: "Expected audience must not be empty")
        }

        guard token.audience.value.contains(where: self.expectedAudiences.contains) else {
            throw JWTError.claimVerificationFailure(
                failedClaim: token.audience,
                reason: "Token was not issued for an expected audience"
            )
        }

        let allowedAudiences = self.trustedAdditionalAudiences.union(self.expectedAudiences)
        guard token.audience.value.allSatisfy(allowedAudiences.contains) else {
            throw JWTError.claimVerificationFailure(
                failedClaim: token.audience,
                reason: "Token includes an untrusted audience"
            )
        }

        if let trustedAuthorizedPresenters = self.trustedAuthorizedPresenters {
            guard let google = token as? GoogleIdentityToken else {
                throw JWTError.generic(
                    identifier: "AuthorizedPresenter",
                    reason: "Authorized presenter validation requires a Google identity token"
                )
            }
            let allowedPresenters = trustedAuthorizedPresenters.union(self.expectedAudiences)
            guard allowedPresenters.contains(google.authorizedPresenter) else {
                throw JWTError.claimVerificationFailure(
                    failedClaim: nil,
                    reason: "Google identity token has an untrusted authorized presenter"
                )
            }
        }
    }
}
