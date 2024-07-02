import Foundation
import JWTKit

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
let keys = try await JWTKeyCollection().use(jwksJSON: json)
