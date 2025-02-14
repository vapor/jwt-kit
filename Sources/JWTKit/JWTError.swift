#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

/// JWT error type.
public struct JWTError: Error, Sendable, Equatable {
    public struct ErrorType: Sendable, Hashable, CustomStringConvertible, Equatable {
        enum Base: String, Sendable, Equatable {
            case claimVerificationFailure
            case signingAlgorithmFailure
            case malformedToken
            case signatureVerificationFailed
            case missingKIDHeader
            case unknownKID
            case invalidJWK
            case invalidBool
            case noKeyProvided
            case missingX5CHeader
            case invalidX5CChain
            case invalidHeaderField
            case unsupportedCurve
            case generic
        }

        let base: Base

        private init(_ base: Base) {
            self.base = base
        }

        public static let claimVerificationFailure = Self(.claimVerificationFailure)
        public static let signingAlgorithmFailure = Self(.signingAlgorithmFailure)
        public static let signatureVerificationFailed = Self(.signatureVerificationFailed)
        public static let missingKIDHeader = Self(.missingKIDHeader)
        public static let malformedToken = Self(.malformedToken)
        public static let unknownKID = Self(.unknownKID)
        public static let invalidJWK = Self(.invalidJWK)
        public static let invalidBool = Self(.invalidBool)
        public static let noKeyProvided = Self(.noKeyProvided)
        public static let missingX5CHeader = Self(.missingX5CHeader)
        public static let invalidX5CChain = Self(.invalidX5CChain)
        public static let invalidHeaderField = Self(.invalidHeaderField)
        public static let unsupportedCurve = Self(.unsupportedCurve)
        public static let generic = Self(.generic)

        public var description: String {
            base.rawValue
        }
    }

    private struct Backing: Sendable, Equatable {
        fileprivate let errorType: ErrorType
        fileprivate let name: String?
        fileprivate let reason: String?
        fileprivate let underlying: Error?
        fileprivate let kid: JWKIdentifier?
        fileprivate let identifier: String?
        fileprivate let failedClaim: (any JWTClaim)?
        fileprivate var curve: (any ECDSACurveType)?

        init(
            errorType: ErrorType,
            name: String? = nil,
            reason: String? = nil,
            underlying: Error? = nil,
            kid: JWKIdentifier? = nil,
            identifier: String? = nil,
            failedClaim: (any JWTClaim)? = nil,
            curve: (any ECDSACurveType)? = nil
        ) {
            self.errorType = errorType
            self.name = name
            self.reason = reason
            self.underlying = underlying
            self.kid = kid
            self.identifier = identifier
            self.failedClaim = failedClaim
            self.curve = curve
        }

        static func == (lhs: JWTError.Backing, rhs: JWTError.Backing) -> Bool {
            lhs.errorType == rhs.errorType
        }
    }

    private var backing: Backing

    public var errorType: ErrorType { backing.errorType }
    public var name: String? { backing.name }
    public var reason: String? { backing.reason }
    public var underlying: (any Error)? { backing.underlying }
    public var kid: JWKIdentifier? { backing.kid }
    public var identifier: String? { backing.identifier }
    public var failedClaim: (any JWTClaim)? { backing.failedClaim }
    public var curve: (any ECDSACurveType)? { backing.curve }

    private init(backing: Backing) {
        self.backing = backing
    }

    private init(errorType: ErrorType) {
        self.backing = .init(errorType: errorType)
    }

    public static func claimVerificationFailure(failedClaim: (any JWTClaim)?, reason: String) -> Self {
        .init(backing: .init(errorType: .claimVerificationFailure, reason: reason, failedClaim: failedClaim))
    }

    public static func signingAlgorithmFailure(_ error: Error) -> Self {
        .init(backing: .init(errorType: .signingAlgorithmFailure, underlying: error))
    }

    public static func malformedToken(reason: String) -> Self {
        .init(backing: .init(errorType: .malformedToken, reason: reason))
    }

    public static let signatureVerificationFailed = Self(errorType: .signatureVerificationFailed)

    public static let missingKIDHeader = Self(errorType: .missingKIDHeader)

    public static func unknownKID(_ kid: JWKIdentifier) -> Self {
        .init(backing: .init(errorType: .unknownKID, kid: kid))
    }

    public static func invalidJWK(reason: String) -> Self {
        .init(backing: .init(errorType: .invalidJWK, reason: reason))
    }

    public static func invalidBool(_ name: String) -> Self {
        .init(backing: .init(errorType: .invalidBool, name: name))
    }

    public static let noKeyProvided = Self(errorType: .noKeyProvided)

    public static let missingX5CHeader = Self(errorType: .missingX5CHeader)

    public static func invalidX5CChain(reason: String) -> Self {
        .init(backing: .init(errorType: .invalidX5CChain, reason: reason))
    }

    public static func invalidHeaderField(reason: String) -> Self {
        .init(backing: .init(errorType: .invalidHeaderField, reason: reason))
    }

    public static func unsupportedCurve(curve: any ECDSACurveType) -> Self {
        .init(backing: .init(errorType: .unsupportedCurve, curve: curve))
    }

    public static func generic(identifier: String, reason: String) -> Self {
        .init(backing: .init(errorType: .generic, reason: reason))
    }

    public static func == (lhs: JWTError, rhs: JWTError) -> Bool {
        lhs.backing == rhs.backing
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
