import Foundation
import Testing

@testable import JWTKit

/// Covers the key material storage behind ``JWK`` and the flat members kept over it.
@Suite("JWK Tests")
struct JWKTests {
    /// Describes the result of turning a JWK into a signer, so it can be asserted as a value.
    static func outcome(_ body: () throws -> (any JWTAlgorithm)?) -> String {
        do {
            guard let algorithm = try body() else { return "nil" }
            return "algorithm(\(algorithm.name))"
        } catch let error as JWTError {
            return "error(\(error.reason ?? "-"))"
        } catch {
            return "error(\(error))"
        }
    }

    static var documentedOutcomes: [(name: String, json: String, outcome: String)] {
        [
            (
                "RSA public key",
                #"{"kty":"RSA","alg":"RS256","kid":"a","n":"\#(rsaModulus)","e":"AQAB"}"#,
                "algorithm(RS256)"
            ),
            (
                "RSA public key, PSS",
                #"{"kty":"RSA","alg":"PS512","kid":"a","n":"\#(rsaModulus)","e":"AQAB"}"#,
                "algorithm(PS512)"
            ),
            (
                "RSA with no alg",
                #"{"kty":"RSA","kid":"a","n":"\#(rsaModulus)","e":"AQAB"}"#,
                "nil"
            ),
            (
                "RSA with a non-RSA alg",
                #"{"kty":"RSA","alg":"ES256","kid":"a","n":"\#(rsaModulus)","e":"AQAB"}"#,
                "nil"
            ),
            (
                "RSA missing its modulus",
                #"{"kty":"RSA","alg":"RS256","kid":"a","e":"AQAB"}"#,
                "error(Missing RSA primitives)"
            ),
            (
                "RSA missing its exponent",
                #"{"kty":"RSA","alg":"RS256","kid":"a","n":"\#(rsaModulus)"}"#,
                "error(Missing RSA primitives)"
            ),
            (
                "EC missing its y coordinate",
                #"{"kty":"EC","alg":"ES256","kid":"a","crv":"P-256","x":"AQAB"}"#,
                "error(Missing ECDSA coordinates)"
            ),
            (
                "EC missing both coordinates",
                #"{"kty":"EC","alg":"ES256","kid":"a","crv":"P-256"}"#,
                "error(Missing ECDSA coordinates)"
            ),
            (
                "OKP public key",
                #"{"kty":"OKP","alg":"EdDSA","kid":"a","crv":"Ed25519","x":"\#(eddsaPublicKeyBase64Url)"}"#,
                "algorithm(EdDSA)"
            ),
            (
                "OKP private key",
                #"{"kty":"OKP","alg":"EdDSA","kid":"a","crv":"Ed25519","x":"\#(eddsaPublicKeyBase64Url)","d":"\#(eddsaPrivateKeyBase64Url)"}"#,
                "algorithm(EdDSA)"
            ),
            (
                "OKP with no curve",
                #"{"kty":"OKP","alg":"EdDSA","kid":"a","x":"\#(eddsaPublicKeyBase64Url)"}"#,
                "error(Invalid EdDSA curve)"
            ),
            (
                "OKP with a non-EdDSA alg",
                #"{"kty":"OKP","alg":"RS256","kid":"a","crv":"Ed25519","x":"\#(eddsaPublicKeyBase64Url)"}"#,
                "nil"
            ),
            (
                "OKP missing its x coordinate",
                #"{"kty":"OKP","alg":"EdDSA","kid":"a","crv":"Ed25519"}"#,
                "nil"
            ),
            (
                "OKP missing x with an invalid curve",
                #"{"kty":"OKP","alg":"EdDSA","kid":"a","crv":"P-256"}"#,
                "error(Invalid EdDSA curve)"
            ),
        ]
    }

    @Test("Each key produces the outcome it always has", arguments: documentedOutcomes)
    func documentedOutcomesHold(testCase: (name: String, json: String, outcome: String)) throws {
        let key = try JWK(json: testCase.json)
        #expect(Self.outcome { try key.getKey() } == testCase.outcome, "\(testCase.name)")
    }

    @Test("The corpus exercises success, nil and failure")
    func corpusIsMeaningful() {
        let outcomes = Set(Self.documentedOutcomes.map(\.outcome))
        #expect(outcomes.contains("algorithm(RS256)"))
        #expect(outcomes.contains("algorithm(EdDSA)"))
        #expect(outcomes.contains("nil"))
        #expect(outcomes.contains { $0.hasPrefix("error(") })
    }

    @Test("Every key round trips through Codable unchanged")
    func roundTrip() throws {
        for testCase in Self.documentedOutcomes {
            let key = try JWK(json: testCase.json)
            let encoded = try JSONEncoder().encode(key)

            let original = try JSONSerialization.jsonObject(with: Data(testCase.json.utf8)) as? [String: String]
            let roundTripped = try JSONSerialization.jsonObject(with: encoded) as? [String: String]

            #expect(original == roundTripped, "\(testCase.name)")
        }
    }

    // MARK: - Unrecognised values

    @Test("An unrecognised kty, alg or crv doesn't fail decoding")
    func unknownValuesAreTolerated() throws {
        let unknowns = [
            (#"{"kty":"AKP","alg":"ML-DSA-65","kid":"pq","x":"AQAB"}"#, "kty", "AKP"),
            (#"{"kty":"EC","alg":"ES256K","kid":"a","crv":"P-256","x":"AQAB","y":"AQAB"}"#, "alg", "ES256K"),
            (#"{"kty":"EC","alg":"ES256","kid":"a","crv":"secp256k1","x":"AQAB","y":"AQAB"}"#, "crv", "secp256k1"),
        ]

        for (json, member, rawValue) in unknowns {
            let key = try JWK(json: json)

            switch member {
            case "kty": #expect(key.keyType.rawValue == rawValue)
            case "alg": #expect(key.algorithm?.rawValue == rawValue)
            default: #expect(key.curve?.rawValue == rawValue)
            }

            // The value survives a round trip rather than being erased.
            let encoded = try JSONEncoder().encode(key)
            let object = try JSONSerialization.jsonObject(with: encoded) as? [String: String]
            #expect(object?[member] == rawValue, "\(member) should survive a round trip")
        }
    }

    @Test("A key type JWTKit doesn't model is inert rather than fatal")
    func unknownKeyTypeIsInert() throws {
        let key = try JWK(json: #"{"kty":"AKP","alg":"ML-DSA-65","kid":"pq","x":"AQAB"}"#)
        #expect(try key.getKey() == nil)
    }

    @Test("An unrecognised value is preserved wherever it arrives from")
    func unknownValuesArePreserved() throws {
        #expect(JWK.KeyType(rawValue: "AKP") == JWK.KeyType.unknown("AKP"))
        #expect(JWK.Algorithm(rawValue: "ES256K") == JWK.Algorithm.unknown("ES256K"))
        #expect(JWK.Curve(rawValue: "secp256k1") == JWK.Curve.unknown("secp256k1"))

        let key = try JWK(json: #"{"kty":"AKP","alg":"ES256K","crv":"secp256k1"}"#)
        #expect(key.keyType.rawValue == "AKP")
        #expect(key.algorithm?.rawValue == "ES256K")
        #expect(key.curve?.rawValue == "secp256k1")
    }

    @Test("Unknown values can also be constructed directly")
    func unknownFactories() throws {
        #expect(JWK.KeyType.unknown("AKP").rawValue == "AKP")
        #expect(JWK.Algorithm.unknown("ES256K").rawValue == "ES256K")
        #expect(JWK.Curve.unknown("secp256k1").rawValue == "secp256k1")

        var key = JWK.rsa(nil, identifier: "a", modulus: nil, exponent: nil)
        key.keyType = .unknown("AKP")
        key.algorithm = .unknown("ES256K")
        key.curve = .unknown("secp256k1")

        let encoded = try JSONSerialization.jsonObject(with: JSONEncoder().encode(key)) as? [String: String]
        #expect(encoded?["kty"] == "AKP")
        #expect(encoded?["alg"] == "ES256K")
        #expect(encoded?["crv"] == "secp256k1")
    }

    @Test("Switching between storages")
    func switchingBetweenStorages() throws {
        var key = try JWK(json: #"{"kty":"RSA","alg":"RS256","kid":"a","n":"\#(rsaModulus)","e":"AQAB"}"#)
        guard case .rsa = key.parameters else {
            Issue.record("expected a typed RSA key")
            return
        }

        // removing a required member demotes the key
        key.exponent = nil
        guard case .loose = key.parameters else {
            Issue.record("expected the key to demote once it lost its exponent")
            return
        }
        #expect(key.exponent == nil)

        // restoring it promotes the key back
        key.exponent = "AQAB"
        guard case .rsa = key.parameters else {
            Issue.record("expected the key to promote once its exponent came back")
            return
        }
        #expect(key.exponent == "AQAB")
    }

    @Test("Changing the key type re-derives the storage")
    func changingKeyType() throws {
        var key = try JWK(json: #"{"kty":"RSA","alg":"RS256","kid":"a","n":"\#(rsaModulus)","e":"AQAB"}"#)

        key.keyType = .octetKeyPair
        guard case .loose = key.parameters else {
            Issue.record("an RSA key's members don't make an octet key pair")
            return
        }
        #expect(key.keyType == .octetKeyPair)
        #expect(key.modulus == rsaModulus, "members should survive the change")
    }

    @Test("The factories produce typed storage")
    func factories() throws {
        guard case .rsa = JWK.rsa(.rs256, identifier: "a", modulus: rsaModulus, exponent: "AQAB").parameters else {
            Issue.record("expected a typed RSA key")
            return
        }

        guard case .loose = JWK.rsa(.rs256, identifier: "a", modulus: nil, exponent: "AQAB").parameters else {
            Issue.record("expected an incomplete RSA key to stay loose")
            return
        }

        guard
            case .okp = JWK.octetKeyPair(
                .eddsa, identifier: "a", x: eddsaPublicKeyBase64Url, curve: .ed25519
            ).parameters
        else {
            Issue.record("expected a typed OKP key")
            return
        }
    }
}
