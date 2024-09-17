import JWTKit

struct TestPayload: JWTPayload, Equatable {
    var sub: SubjectClaim
    var name: String
    var admin: Bool
    var exp: ExpirationClaim

    func verify(using _: some JWTAlgorithm) throws {
        try exp.verifyNotExpired()
    }
}
