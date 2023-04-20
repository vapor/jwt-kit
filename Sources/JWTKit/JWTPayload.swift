import Foundation

/// A JWT payload is a Publically Readable set of claims
/// Each variable represents a claim.
public protocol JWTPayload: Codable {
    /// Verifies that the payload's claims are correct or throws an error.
    func verify(using signer: JWTSigner) throws
    
    /// JSONDecoder that is used to decode the JWTPayload Data
    /// Override this in order to use a custom JSONDecoder for JWTPayload decoding
    /// This is especially usefuly when wanting to customize the `dateDecodingStrategy` for example
    static func jsonDecoder() -> JSONDecoder
}

extension JWTPayload {
    public static func jsonDecoder() -> JSONDecoder {
        let jsonDecoder = JSONDecoder()
        jsonDecoder.dateDecodingStrategy = .secondsSince1970
        return jsonDecoder
    }
}
