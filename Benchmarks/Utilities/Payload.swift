import JWTKit

package struct Payload: JWTPayload {
    package let name: String
    package let admin: Bool

    package init(name: String, admin: Bool) {
        self.name = name
        self.admin = admin
    }

    package func verify(using signer: some JWTAlgorithm) async throws {
        // nothing to verify
    }
}
