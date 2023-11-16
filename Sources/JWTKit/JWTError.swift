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
            case generic
        }
        
        internal let base: Base
        
        private init(_ base: Base) {
            self.base = base
        }
        
        public static let claimVerificationFailure = Self(.claimVerificationFailure)
        public static let signingAlgorithmFailure = Self(.signingAlgorithmFailure)
        public static let malformedToken = Self(.malformedToken)
        public static let signatureVerificationFailed = Self(.signatureVerifictionFailed)
        public static let missingKIDHeader = Self(.missingKIDHeader)
        public static let unknownKID = Self(.unknownKID)
        public static let invalidJWK = Self(.invalidJWK)
        public static let invalidBool = Self(.invalidBool)
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
        
        func copy() -> Self {
            let new = Self.init(errorType: self.errorType)
            new.name = self.name
            new.reason = self.reason
            new.underlying = self.underlying
            new.kid = self.kid
            new.identifier = self.identifier
            return new
        }
    }
    
    private var backing: Backing
    
    private mutating func copyBackingStorageIfNecessary() {
        if !isKnownUniquelyReferenced(&self.backing) {
            self.backing = self.backing.copy()
        }
    }
    
    public internal(set) var errorType: ErrorType {
        get { self.backing.errorType }
        set {
            self.copyBackingStorageIfNecessary()
            self.backing.errorType = newValue
        }
    }
    
    public internal(set) var name: String? {
        get { self.backing.name }
        set {
            self.copyBackingStorageIfNecessary()
            self.backing.name = newValue
        }
    }
    
    public internal(set) var reason: String? {
        get { self.backing.reason }
        set {
            self.copyBackingStorageIfNecessary()
            self.backing.reason = newValue
        }
    }
    
    public internal(set) var underlying: Error? {
        get { self.backing.underlying }
        set {
            self.copyBackingStorageIfNecessary()
            self.backing.underlying = newValue
        }
    }
    
    public internal(set) var kid: JWKIdentifier? {
        get { self.backing.kid }
        set {
            self.copyBackingStorageIfNecessary()
            self.backing.kid = newValue
        }
    }
    
    public internal(set) var identifier: String? {
        get { self.backing.identifier }
        set {
            self.copyBackingStorageIfNecessary()
            self.backing.identifier = newValue
        }
    }
    
    public internal(set) var failedClaim: (any JWTClaim)? {
        get { self.backing.failedClaim }
        set {
            self.copyBackingStorageIfNecessary()
            self.backing.failedClaim = newValue
        }
    }
    
    init(errorType: ErrorType) {
        self.backing = .init(errorType: errorType)
    }
    
    package static func claimVerificationFailure(failedClaim: any JWTClaim, reason: String) -> Self {
        var new = Self(errorType: .claimVerificationFailure)
        new.failedClaim = failedClaim
        new.reason = reason
        return new
    }
    
    package static func signingAlgorithmFailure(_ error: Error) -> Self {
        var new = Self(errorType: .signingAlgorithmFailure)
        new.underlying = error
        return new
    }
    
    package static let malformedToken = Self(errorType: .malformedToken)
    
    package static let signatureVerificationFailed = Self(errorType: .signatureVerificationFailed)
    
    package static let missingKIDHeader = Self(errorType: .missingKIDHeader)
    
    package static func unknownKID(_ kid: JWKIdentifier) -> Self {
        var new = Self(errorType: .unknownKID)
        new.kid = kid
        return new
    }
    
    package static let invalidJWK = Self(errorType: .invalidJWK)
    
    package static func invalidBool(_ name: String) -> Self {
        var new = Self(errorType: .invalidBool)
        new.name = name
        return new
    }
    
    package static func generic(identifier: String, reason: String) -> Self {
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
