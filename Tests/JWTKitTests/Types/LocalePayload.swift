import JWTKit
import Foundation

struct LocalePayload: Codable {
    var locale: LocaleClaim
}

extension LocalePayload {
    static func from(_ string: String) throws -> LocalePayload {
        let data = string.data(using: .utf8)!
        return try JSONDecoder().decode(LocalePayload.self, from: data)
    }
}
