/// A JWT payload is a Publically Readable set of claims.
/// Each variable represents a claim.
public protocol JWTPayload: Codable, Sendable {
    /// Verifies that the payload's claims are correct or throws an error.
    func verify(using algorithm: some JWTAlgorithm) async throws
}
