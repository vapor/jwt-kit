import XCTest
import Crypto
#if os(Linux)
import FoundationNetworking
#endif
@testable import JWTKit

class JWTKitMigrationTests: XCTestCase {
    func testVerifyingCryptoKey() async throws {
        struct Foo: AsyncJWTPayload {
            var bar: Int
            func verify<Algorithm: JWTAlgorithm>(using signer: Algorithm) async throws { }
            func verify<Algorithm: JWTAlgorithm>(using signer: Algorithm) throws { }
        }
        
        // ecdsa key
        let x = "0tu_H2ShuV8RIgoOxFneTdxmQQYsSk5LdCPuEIBXT-hHd0ufc_OwjEbqilsYnTdm"
        let y = "RWRZz-tP83N0CGwroGyFVgH3PYAO6Oewpu4Xf6EXCp4-sU8uWegwjd72sBK6axj7"
        
        let privateKey = "k-1LAHQRSSMcyaouYK0YOzRbUKj6ISnvihO2XdLQZHQgMt9BkuCT0-539FSHmJxg"
        
        let cryptoKey = try P384.Signing.PrivateKey(rawRepresentation: Data(privateKey.utf8).base64URLDecodedBytes())
        let kwtKey = try ES384PrivateKey(backing: cryptoKey)
        
        XCTAssertEqual(kwtKey.parameters?.x, x)
        XCTAssertEqual(kwtKey.parameters?.y, y)
        
        let privateSigners = JWTKeyCollection()
        await privateSigners.add(ecdsa: kwtKey)
        
        let jwt = try await privateSigners.sign(Foo(bar: 42), kid: "vapor")
        
        // verify using jwks without alg
        let jwksString = """
    {
        "keys": [
            {
                "kty": "EC",
                "use": "sig",
                "kid": "vapor",
                "x": "\(x)",
                "y": "\(y)"
             }
        ]
    }
    """
        
        let signers = JWTKeyCollection()
        try await signers.add(jwksJSON: jwksString)
        let foo = try await signers.verify(jwt, as: Foo.self)
        XCTAssertEqual(foo.bar, 42)
    }
}
