#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

extension JWTParser {
    func parseVerificationFields(from header: ArraySlice<UInt8>) throws -> MandatoryVerificationFields {
        do {
            return try jsonDecoder.decode(MandatoryVerificationFields.self, from: header.span.base64URLDecodedData())
        } catch {
            throw JWTError.malformedToken(reason: "Couldn't decode alg and/or kid from JWT with error: \(String(describing: error)).")
        }
    }
}

struct MandatoryVerificationFields: Codable {
    let alg: String?
    let kid: String?
}
