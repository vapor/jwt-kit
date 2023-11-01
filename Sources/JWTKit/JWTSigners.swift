// import Foundation

// /// A collection of signers labeled by `kid`.
// public final class JWTSigners {
//     /// Internal storage.
//     private enum Signer {
//         case jwt(JWTSigner)
//         case jwk(JWKSigner)
//     }

//     private var storage: [JWKIdentifier: Signer]
//     private var `default`: Signer?

//     /// The default JSON encoder. Used as:
//     ///
//     /// - The default for any ``JWTSigner`` which does not specify its own encoder.
//     public let defaultJSONEncoder: any JWTJSONEncoder

//     /// The default JSON decoder. Used for:
//     ///
//     /// - Parsing the JSON form of a JWKS (see ``JWTSigners/use(jwksJSON:)``.
//     /// - Decoding unverified payloads without a signer (see ``JWTSigners/unverified(_:as:)-2gqbz``).
//     /// - Decoding token headers to determine a key type (see ``JWTSigners/verify(_:as:)-38to``).
//     /// - The default for any``JWTSigner`` which does not specify its own encoder.
//     public let defaultJSONDecoder: any JWTJSONDecoder

//     /// Create a new ``JWTSigners``.
//     public init() {
//         self.storage = [:]
//         self.defaultJSONEncoder = .defaultForJWT
//         self.defaultJSONDecoder = .defaultForJWT
//     }

//     /// Create a new ``JWTSigners`` with specific JSON coders.
//     public init(defaultJSONEncoder: any JWTJSONEncoder, defaultJSONDecoder: any JWTJSONDecoder) {
//         self.storage = [:]
//         self.defaultJSONEncoder = defaultJSONEncoder
//         self.defaultJSONDecoder = defaultJSONDecoder
//     }

//     /// Adds a new signer.
//     public func use(
//         _ signer: JWTSigner,
//         kid: JWKIdentifier? = nil,
//         isDefault: Bool? = nil
//     ) {
//         signer.jsonEncoder = signer.jsonEncoder ?? self.defaultJSONEncoder
//         signer.jsonDecoder = signer.jsonDecoder ?? self.defaultJSONDecoder

//         if let kid = kid {
//             self.storage[kid] = .jwt(signer)
//         }
//         switch (self.default, isDefault) {
//         case (.none, .none), (_, .some(true)):
//             self.default = .jwt(signer)
//         default: break
//         }
//     }

//     /// Adds a `JWKS` (JSON Web Key Set) to this signers collection
//     /// by first decoding the JSON string.
//     public func use(jwksJSON json: String) throws {
//         let jwks = try self.defaultJSONDecoder.decode(JWKS.self, from: Data(json.utf8))
//         try self.use(jwks: jwks)
//     }

//     /// Adds a `JWKS` (JSON Web Key Set) to this signers collection.
//     public func use(jwks: JWKS) throws {
//         try jwks.keys.forEach { try self.use(jwk: $0) }
//     }

//     /// Adds a `JWK` (JSON Web Key) to this signers collection.
//     public func use(
//         jwk: JWK,
//         isDefault: Bool? = nil
//     ) throws {
//         guard let kid = jwk.keyIdentifier else {
//             throw JWTError.invalidJWK
//         }
//         let signer = JWKSigner(jwk: jwk, jsonEncoder: self.defaultJSONEncoder, jsonDecoder: self.defaultJSONDecoder)
//         self.storage[kid] = .jwk(signer)
//         switch (self.default, isDefault) {
//         case (.none, .none), (_, .some(true)):
//             self.default = .jwk(signer)
//         default: break
//         }
//     }

//     /// Gets a signer for the supplied `kid`, if one exists.
//     public func get(kid: JWKIdentifier? = nil, alg: String? = nil) -> JWTSigner? {
//         let signer: Signer
//         if let kid = kid, let stored = self.storage[kid] {
//             signer = stored
//         } else if let d = self.default {
//             signer = d
//         } else {
//             return nil
//         }
//         switch signer {
//         case let .jwt(jwt):
//             return jwt
//         case let .jwk(jwk):
//             return jwk.signer(for: alg.flatMap { JWK.Algorithm(rawValue: $0) })
//         }
//     }

//     public func require(kid: JWKIdentifier? = nil, alg: String? = nil) throws -> JWTSigner {
//         guard let signer = self.get(kid: kid, alg: alg) else {
//             if let kid = kid {
//                 throw JWTError.unknownKID(kid)
//             } else {
//                 throw JWTError.missingKIDHeader
//             }
//         }
//         return signer
//     }

//     public func unverified<Payload>(
//         _ token: String,
//         as _: Payload.Type = Payload.self
//     ) throws -> Payload
//         where Payload: JWTPayload
//     {
//         try unverified([UInt8](token.utf8))
//     }

//     public func unverified<Payload>(
//         _ token: some DataProtocol,
//         as _: Payload.Type = Payload.self
//     ) throws -> Payload
//         where Payload: JWTPayload
//     {
//         try JWTParser(token: token).payload(as: Payload.self, jsonDecoder: defaultJSONDecoder)
//     }

//     public func verify<Payload>(
//         _ token: String,
//         as _: Payload.Type = Payload.self
//     ) throws -> Payload
//         where Payload: JWTPayload
//     {
//         try verify([UInt8](token.utf8), as: Payload.self)
//     }

//     public func verify<Payload>(
//         _ token: some DataProtocol,
//         as _: Payload.Type = Payload.self
//     ) throws -> Payload
//         where Payload: JWTPayload
//     {
//         let parser = try JWTParser(token: token)
//         let header = try parser.header(jsonDecoder: self.defaultJSONDecoder)
//         let signer = try self.require(kid: header.kid, alg: header.alg)
//         return try signer.verify(parser: parser)
//     }

//     public func sign(
//         _ payload: some JWTPayload,
//         typ: String = "JWT",
//         kid: JWKIdentifier? = nil
//     ) throws -> String {
//         let signer = try self.require(kid: kid)
//         return try signer.sign(payload, typ: typ, kid: kid)
//     }
// }
