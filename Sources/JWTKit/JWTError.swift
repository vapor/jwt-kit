import Foundation

public struct JWTError: Error, CustomStringConvertible, LocalizedError, Equatable {
    let backing: Backing

    public static func claimVerificationFailure(name: String, reason: String) -> Self { .init(backing: .claimVerificationFailure(name: name, reason: reason)) }
    public static func signingAlgorithmFailure(_ error: Error) -> Self { .init(backing: .signingAlgorithmFailure(error)) }
    public static let malformedToken: Self = .init(backing: .malformedToken)
    public static let signatureVerificationFailed: Self = .init(backing: .signatureVerifictionFailed)
    public static let missingKIDHeader: Self = .init(backing: .missingKIDHeader)
    public static func unknownKID(_ kid: JWKIdentifier) -> Self { .init(backing: .unknownKID(kid)) }
    public static let invalidJWK: Self = .init(backing: .invalidJWK)
    public static func invalidBool(_ str: String) -> Self { .init(backing: .invalidBool(str)) }
    public static func generic(identifier: String, reason: String) -> Self { .init(backing: .generic(identifier: identifier, reason: reason)) }

    enum Backing: Equatable {
        case claimVerificationFailure(name: String, reason: String)
        case signingAlgorithmFailure(Error)
        case malformedToken
        case signatureVerifictionFailed
        case missingKIDHeader
        case unknownKID(JWKIdentifier)
        case invalidJWK
        case invalidBool(String)
        case generic(identifier: String, reason: String)
        
        static func == (lhs: JWTError.Backing, rhs: JWTError.Backing) -> Bool {
            switch (lhs, rhs) {
            case let (.claimVerificationFailure(name1, reason1), .claimVerificationFailure(name2, reason2)):
                name1 == name2 && reason1 == reason2
            case let (.signingAlgorithmFailure(error1), .signingAlgorithmFailure(error2)):
                error1.localizedDescription == error2.localizedDescription
            case (.malformedToken, .malformedToken):
                true
            case (.signatureVerifictionFailed, .signatureVerifictionFailed):
                true
            case (.missingKIDHeader, .missingKIDHeader):
                true
            case let (.unknownKID(kid1), .unknownKID(kid2)):
                kid1 == kid2
            case (.invalidJWK, .invalidJWK):
                true
            case let (.invalidBool(str1), .invalidBool(str2)):
                str1 == str2
            case let (.generic(identifier1, reason1), .generic(identifier2, reason2)):
                identifier1 == identifier2 && reason1 == reason2
            default:
                false
            }
        }
    }

    public var reason: String {
        switch self.backing {
        case let .claimVerificationFailure(name, reason):
            "Claim verification failed for \(name): \(reason)"
        case let .signingAlgorithmFailure(error):
            "Signing algorithm failure: \(error)"
        case .malformedToken:
            "Malformed token"
        case .signatureVerifictionFailed:
            "Signature verification failed"
        case .missingKIDHeader:
            "Missing KID header"
        case let .unknownKID(kid):
            "Unknown KID: \(kid)"
        case .invalidJWK:
            "Invalid JWK"
        case let .invalidBool(str):
            "Invalid bool: \(str)"
        case let .generic(identifier, reason):
            "\(identifier): \(reason)"
        }
    }

    public var description: String {
        "JWTKit error: \(self.reason)"
    }

    public var errorDescription: String? {
        self.description
    }
}
