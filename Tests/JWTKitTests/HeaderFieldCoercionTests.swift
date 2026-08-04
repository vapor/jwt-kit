import Foundation
import JWTKit
import Testing

@Suite("Header field coercion")
struct HeaderFieldCoercionTests {

    static let mixedArrays: [JWTHeaderField] = [
        .array([.string("a"), .int(1)]),
        .array([.int(1), .string("a")]),
        .array([.string("a"), .null]),
        .array([.string("a"), .bool(true)]),
        .array([.string("a"), .array([.string("b")])]),
        .array([.string("a"), .object(["b": .string("c")])]),
        .array([.int(1)]),
    ]

    @Test("Mixed-type crit is rejected rather than filtered", arguments: Self.mixedArrays)
    func mixedCritIsNil(_ field: JWTHeaderField) throws {
        #expect(JWTHeader(fields: ["crit": field]).crit == nil)
    }

    @Test("Mixed-type x5c is rejected rather than filtered", arguments: Self.mixedArrays)
    func mixedX5CIsNil(_ field: JWTHeaderField) throws {
        #expect(JWTHeader(fields: ["x5c": field]).x5c == nil)
    }

    @Test("All-string crit and x5c still read normally")
    func homogeneousArraysStillWork() throws {
        let header = JWTHeader(fields: [
            "crit": .array([.string("a"), .string("b")]),
            "x5c": .array([.string("cert-a"), .string("cert-b")]),
        ])
        #expect(header.crit == ["a", "b"])
        #expect(header.x5c == ["cert-a", "cert-b"])
    }

    @Test("Empty and absent arrays are unchanged")
    func emptyAndAbsent() throws {
        #expect(JWTHeader(fields: ["crit": .array([])]).crit == [])
        #expect(JWTHeader(fields: [:]).crit == nil)
        #expect(JWTHeader(fields: ["crit": .string("a")]).crit == nil)
    }

    @Test("Mixed-type values are rejected when parsed from a token")
    func mixedValuesFromToken() throws {
        func b64(_ s: String) -> String {
            Data(s.utf8).base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }
        struct Payload: JWTPayload {
            var sub: String?
            func verify(using _: some JWTAlgorithm) throws {}
        }

        let header = #"{"alg":"HS256","crit":["a",1],"x5c":["cert",null]}"#
        let token = "\(b64(header)).\(b64(#"{"sub":"1"}"#)).AAAA"
        let parsed = try DefaultJWTParser().parse(Array(token.utf8), as: Payload.self)

        #expect(parsed.header.crit == nil)
        #expect(parsed.header.x5c == nil)
    }
}
