import Foundation

/// JWT error type.
/// @unchecked Sendable is fine as we're using Copy on Write semantics.
public struct JWTError: Error, @unchecked Sendable {
    public struct ErrorType: Sendable, Hashable, CustomStringConvertible {
        enum Base: Sendable, Hashable {
            case claimVerificationFailure
            case signingAlgorithmFailure
            case malformedToken
            case signatureVerifictionFailed
            case missingKIDHeader
            case unknownKID
            case invalidJWK
            case invalidBool
            case noKeyProvided
            case missingX5CHeader
            case invalidX5CChain
            case invalidHeaderField
            case generic
        }

        let base: Base

        private init(_ base: Base) {
            self.base = base
        }

        public static let claimVerificationFailure = Self(.claimVerificationFailure)
        public static let signingAlgorithmFailure = Self(.signingAlgorithmFailure)
        public static let signatureVerificationFailed = Self(.signatureVerifictionFailed)
        public static let missingKIDHeader = Self(.missingKIDHeader)
        public static let malformedToken = Self(.malformedToken)
        public static let unknownKID = Self(.unknownKID)
        public static let invalidJWK = Self(.invalidJWK)
        public static let invalidBool = Self(.invalidBool)
        public static let noKeyProvided = Self(.noKeyProvided)
        public static let missingX5CHeader = Self(.missingX5CHeader)
        public static let invalidX5CChain = Self(.invalidX5CChain)
        public static let invalidHeaderField = Self(.invalidHeaderField)
        public static let generic = Self(.generic)

        public var description: String {
            switch self.base {
            case .claimVerificationFailure:
                "claimVerificationFailure"
            case .signingAlgorithmFailure:
                "signingAlgorithmFailure"
            case .malformedToken:
                "malformedToken"
            case .signatureVerifictionFailed:
                "signatureVerifictionFailed"
            case .missingKIDHeader:
                "missingKIDHeader"
            case .unknownKID:
                "unknownKID"
            case .invalidJWK:
                "invalidJWK"
            case .invalidBool:
                "invalidBool"
            case .noKeyProvided:
                "noKeyProvided"
            case .invalidX5CChain:
                "invalidX5CChain"
            case .invalidHeaderField:
                "invalidHeaderField"
            case .missingX5CHeader:
                "missingX5CHeader"
            case .generic:
                "generic"
            }
        }
    }

    private final class Backing {
        fileprivate var errorType: ErrorType
        fileprivate var name: String?
        fileprivate var reason: String?
        fileprivate var underlying: Error?
        fileprivate var kid: JWKIdentifier?
        fileprivate var identifier: String?
        fileprivate var failedClaim: (any JWTClaim)?

        init(errorType: ErrorType) {
            self.errorType = errorType
        }
    }

    private var backing: Backing

    public internal(set) var errorType: ErrorType {
        get { self.backing.errorType }
        set { self.backing.errorType = newValue }
    }

    public internal(set) var name: String? {
        get { self.backing.name }
        set { self.backing.name = newValue }
    }

    public internal(set) var reason: String? {
        get { self.backing.reason }
        set { self.backing.reason = newValue }
    }

    public internal(set) var underlying: Error? {
        get { self.backing.underlying }
        set { self.backing.underlying = newValue }
    }

    public internal(set) var kid: JWKIdentifier? {
        get { self.backing.kid }
        set { self.backing.kid = newValue }
    }

    public internal(set) var identifier: String? {
        get { self.backing.identifier }
        set { self.backing.identifier = newValue }
    }

    public internal(set) var failedClaim: (any JWTClaim)? {
        get { self.backing.failedClaim }
        set { self.backing.failedClaim = newValue }
    }

    init(errorType: ErrorType) {
        self.backing = .init(errorType: errorType)
    }

    public static func claimVerificationFailure(failedClaim: (any JWTClaim)?, reason: String) -> Self {
        var new = Self(errorType: .claimVerificationFailure)
        new.failedClaim = failedClaim
        new.reason = reason
        return new
    }

    public static func signingAlgorithmFailure(_ error: Error) -> Self {
        var new = Self(errorType: .signingAlgorithmFailure)
        new.underlying = error
        return new
    }

    public static func malformedToken(reason: String) -> Self {
        var new = Self(errorType: .malformedToken)
        new.reason = reason
        return new
    }

    public static let malformedToken = Self(errorType: .malformedToken)

    public static let signatureVerificationFailed = Self(errorType: .signatureVerificationFailed)

    public static let missingKIDHeader = Self(errorType: .missingKIDHeader)

    public static func unknownKID(_ kid: JWKIdentifier) -> Self {
        var new = Self(errorType: .unknownKID)
        new.kid = kid
        return new
    }

    public static let invalidJWK = Self(errorType: .invalidJWK)

    public static func invalidBool(_ name: String) -> Self {
        var new = Self(errorType: .invalidBool)
        new.name = name
        return new
    }

    public static let noKeyProvided = Self(errorType: .noKeyProvided)

    public static let missingX5CHeader = Self(errorType: .missingX5CHeader)

    public static func invalidX5CChain(reason: String) -> Self {
        var new = Self(errorType: .invalidX5CChain)
        new.reason = reason
        return new
    }

    public static func invalidHeaderField(reason: String) -> Self {
        var new = Self(errorType: .invalidHeaderField)
        new.reason = reason
        return new
    }

    public static func generic(identifier: String, reason: String) -> Self {
        var new = Self(errorType: .generic)
        new.identifier = identifier
        new.reason = reason
        return new
    }
}

extension JWTError: CustomStringConvertible {
    public var description: String {
        var result = #"JWTKitError(errorType: \#(self.errorType)"#

        if let name {
            result.append(", name: \(String(reflecting: name))")
        }

        if let failedClaim {
            result.append(", failedClaim: \(String(reflecting: failedClaim))")
        }

        if let reason {
            result.append(", reason: \(String(reflecting: reason))")
        }

        if let underlying {
            result.append(", underlying: \(String(reflecting: underlying))")
        }

        if let kid {
            result.append(", kid: \(String(reflecting: kid))")
        }

        if let identifier {
            result.append(", identifier: \(String(reflecting: identifier))")
        }

        result.append(")")

        return result
    }
}
