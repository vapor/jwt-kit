import Foundation
import SwiftASN1
import X509

/// A X5CVerifier that correctly verifies StoreKit 2 receipts and App Store Server Notifications
/// as specified in https://developer.apple.com/documentation/appstoreservernotifications
public class AppStoreX5CVerifier: X5CVerifier {
    
    /// A payload that only contains the `signedDate`
    /// in order to use it as a reference for the expiration of the used certificates
    /// Background: The StoreKit 2 receipts are signed at a specific date with
    /// the then valid certificates from Apple. At some point it is possible that these
    /// Apple certificats expire even before the payload expires. Therefore we need
    /// to check that the certificates were valid at the time when Apple signed the
    /// receipt.
    struct AppStorePayload: Codable, JWTPayload {
        func verify(using signer: JWTAlgorithm) async throws { }
        
        let signedDate: Date
    }
    
    /// Verify a JWS with the `x5c` header parameter against the trusted root
    /// certificates.
    ///
    /// - Parameters:
    ///   - token: The JWS to verify.
    ///   - payload: The type to decode from the token payload.
    /// - Returns: The decoded payload, if verified.
    override public func verifyJWS<Payload: JWTPayload>(
        _ token: String,
        as _: Payload.Type = Payload.self
    ) async throws -> Payload {
        try await verifyJWS(token, as: Payload.self, jsonDecoder: .defaultForAppStoreJWT)
    }
    
    /// Verify a JWS with `x5c` claims against the
    /// trusted root certificates.
    ///
    /// - Parameters:
    ///   - token: The JWS to verify.
    ///   - payload: The type to decode from the token payload.
    /// - Returns: The decoded payload, if verified.
    override public func verifyJWS<Payload>(
        _ token: some DataProtocol,
        as _: Payload.Type = Payload.self
    ) async throws -> Payload
        where Payload: JWTPayload
    {
        try await verifyJWS(token, as: Payload.self, jsonDecoder: .defaultForAppStoreJWT)
    }
    
    /// Verify a JWS from the App Store or StoreKit 2 with `x5c` claims against the
    /// trusted root certificates
    ///
    /// - Parameters:
    ///   - token: The JWS to verify.
    ///   - payload: The type to decode from the token payload.
    /// - Returns: The decoded payload, if verified.
    override public func verifyJWS<Payload>(
        _ token: some DataProtocol,
        as _: Payload.Type = Payload.self,
        jsonDecoder: any JWTJSONDecoder
    ) async throws -> Payload
        where Payload: JWTPayload
    {
        // Parse the payload to get the signedDate
        let parser = try JWTParser(token: token)
        let payload = try parser.payload(as: AppStorePayload.self, jsonDecoder: .defaultForAppStoreJWT)
        
        return try await verifyJWS(parser, as: Payload.self, jsonDecoder: jsonDecoder) {
            // Check the expiration of the used certificates against
            // the signing date of the payload rather than the current date.
            // See `AppStorePayload` documentation for motivation.
            RFC5280Policy(validationTime: payload.signedDate)
        }
    }
}


extension JWTJSONDecoder where Self == JSONDecoder {
    /// AppStore/StoreKit 2 payloads have a `millisecondsSince1970` encoded date format
    static var defaultForAppStoreJWT: any JWTJSONDecoder {
        let decoder = JSONDecoder()
        decoder.dateDecodingStrategy = .millisecondsSince1970
        return decoder
    }
}
