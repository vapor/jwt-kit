protocol Signer {
    /// The algorithm used by the signer.
    var algorithm: JWTAlgorithm { get }

    /// The JSON encoder used by the signer.
    var jsonEncoder: (any JWTJSONEncoder)? { get }

    /// The JSON decoder used by the signer.
    var jsonDecoder: (any JWTJSONDecoder)? { get }

    /// Sign a JWTPayload instance and return the resulting token as a String.
    func sign(_ payload: some JWTPayload, typ: String, kid: JWKIdentifier?, cty: String?) throws -> String

    /// Verify a token string and return the decoded payload of a specified type.
    func verify<T: JWTPayload>(_ token: String, as payloadType: T.Type) throws -> T

    /// Verify a token using a DataProtocol instance and return the decoded payload of a specified type.
    func verify<T: JWTPayload>(_ token: some DataProtocol, as payloadType: T.Type) throws -> T

    /// Get the unverified payload from a token string of a specified type.
    func unverified<T: JWTPayload>(_ token: String, as payloadType: T.Type) throws -> T

    /// Get the unverified payload from a token using a DataProtocol instance of a specified type.
    func unverified<T: JWTPayload>(_ token: some DataProtocol, as payloadType: T.Type) throws -> T
}
