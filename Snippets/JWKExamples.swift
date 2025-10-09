import JWTKit

#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

let rsaModulus = "..."

let json = """
    {
        "keys": [
            {"kty": "RSA", "alg": "RS256", "kid": "a", "n": "\(rsaModulus)", "e": "AQAB"},
            {"kty": "RSA", "alg": "RS512", "kid": "b", "n": "\(rsaModulus)", "e": "AQAB"},
        ]
    }
    """

// Create key collection and add JWKS
let keys = try await JWTKeyCollection().add(jwksJSON: json)
