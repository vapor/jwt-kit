import JWTKit

struct BoolPayload: Decodable {
    var trueStr: BoolClaim
    var trueBool: BoolClaim
    var falseStr: BoolClaim
    var falseBool: BoolClaim
}
