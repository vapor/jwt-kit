import JWTKit

package struct Payload: JWTPayload {
    package let name: String
    package let admin: Bool

    func verify(using signer: some JWTAlgorithm) async throws {
        // nothing to verify
    }
}
