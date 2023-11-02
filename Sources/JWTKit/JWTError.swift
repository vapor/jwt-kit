import Foundation

public enum JWTError: Error, CustomStringConvertible, LocalizedError {
    case claimVerificationFailure(name: String, reason: String)
    case signingAlgorithmFailure(Error)
    case malformedToken
    case signatureVerifictionFailed
    case missingKIDHeader
    case unknownKID(JWKIdentifier)
    case invalidJWK
    case invalidBool(String)
    case generic(identifier: String, reason: String)

    public var reason: String {
        switch self {
        case let .claimVerificationFailure(name, reason):
            return "\(name) claim verification failed: \(reason)"
        case let .signingAlgorithmFailure(error):
            return "signing algorithm error: \(error)"
        case .malformedToken:
            return "malformed JWT"
        case .signatureVerifictionFailed:
            return "signature verification failed"
        case .missingKIDHeader:
            return "missing kid field in header"
        case let .unknownKID(kid):
            return "unknown kid: \(kid)"
        case .invalidJWK:
            return "invalid JWK"
        case let .invalidBool(str):
            return "invalid boolean value: \(str)"
        case let .generic(identifier, reason):
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
