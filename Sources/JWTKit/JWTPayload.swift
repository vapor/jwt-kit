/// A JWT payload is a Publically Readable set of claims
/// Each variable represents a claim.
/// - Warning: Requirements changed in v5 to be async. Please also conform to ``AsyncJWTPayload`` while on v4, and remove the ``AsyncJWTPayload`` conformance once you do update to v5.
public protocol JWTPayload: Codable {
    /// Verifies that the payload's claims are correct or throws an error.
    func verify(using signer: JWTSigner) throws
}

/// A transitionary protocol with sync and async requirements.
///
/// This protocol should be dropped once you are finished migrating to v5, as it'll have been renamed back to ``JWTPayload``, but with a single async requirement. In order to support both versions v4 and v5 in a library, do not implement the requirements of ``JWTPayload`` as ``JWTSigner`` is no longer available in v5.
public protocol AsyncJWTPayload: Codable {
    func verify<Algorithm: JWTAlgorithm>(using signer: Algorithm) throws
    
    /// Verifies that the payload's claims are correct or throws an error.
    func verify<Algorithm: JWTAlgorithm>(using algorithm: Algorithm) async throws
}
