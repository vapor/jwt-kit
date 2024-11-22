#if !canImport(Foundation)
    import FoundationEssentials
#else
    import Foundation
#endif

public protocol JWKRepresentable {
    func toJWKRepresentation(kid: String?) -> JWK
}

extension JWK {
    public func toJSONString() throws -> String {
        let data = try JSONEncoder().encode(self)
        guard let string = String(data: data, encoding: .utf8) else {
            throw EncodingError.invalidValue(
                self, EncodingError.Context(codingPath: [], debugDescription: "Failed to encode JWK to JSON string")
            )
        }
        return string
    }
    
    public func toJSONData() throws -> Data {
        try JSONEncoder().encode(self)
    }
}
