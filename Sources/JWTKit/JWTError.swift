import Foundation

public enum JWTError: Error, CustomStringConvertible, LocalizedError {
    case claimVerificationFailure(name: String, reason: String)
    case signingAlgorithmFailure(Error)
    case malformedToken
    case signatureVerificationFailed
    case missingKIDHeader
    case unknownKID(JWKIdentifier)
    case invalidJWK
    case invalidBool(String)
    case generic(identifier: String, reason: String)

    public var reason: String {
        switch self {
        case .claimVerificationFailure(let name, let reason):
            return "\(name) claim verification failed: \(reason)"
        case .signingAlgorithmFailure(let error):
            return "signing algorithm error: \(error)"
        case .malformedToken:
            return "malformed JWT"
        case .signatureVerificationFailed:
            return "signature verification failed"
        case .missingKIDHeader:
            return "missing kid field in header"
        case .unknownKID(let kid):
            return "unknown kid: \(kid)"
        case .invalidJWK:
            return "invalid JWK"
        case .invalidBool(let str):
            return "invalid boolean value: \(str)"
        case .generic(let identifier, let reason):
                return "missing '\(identifier). \(reason)"
        }
    }

    public var description: String {
        return "JWTKit error: \(self.reason)"
    }
    
    public var errorDescription: String? {
        return self.description
    }
}
