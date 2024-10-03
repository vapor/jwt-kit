import JWTKit

struct ExpirationPayload: JWTPayload {
    var exp: ExpirationClaim

    func verify(using _: some JWTAlgorithm) throws {
        try self.exp.verifyNotExpired()
    }
}
