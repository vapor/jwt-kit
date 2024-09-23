import BigInt
import Foundation
@testable import JWTKit
import Testing

func wycheproof(fileName: String, testFunction: (TestGroup) throws -> Void) throws {
    let testsDirectory: String = URL(fileURLWithPath: "\(#filePath)").pathComponents.dropLast(2).joined(separator: "/")
    let path = "\(testsDirectory)/TestVectors/\(fileName).json"
    let fileHandle = try FileHandle(forReadingFrom: URL(fileURLWithPath: path))

    let data = fileHandle.readDataToEndOfFile()
    fileHandle.closeFile()

    let testVectors = try JSONDecoder().decode(TestVectors.self, from: data)

    for testGroup in testVectors.testGroups {
        try testFunction(testGroup)
    }
}

func testPrimeFactors(_ testGroup: TestGroup) throws {
    guard
        let n = BigUInt(testGroup.n, radix: 16),
        let e = BigUInt(testGroup.e, radix: 16),
        let d = BigUInt(testGroup.d, radix: 16)
    else {
        Issue.record("Failed to extract or parse modulus 'n', public exponent 'e', or private exponent 'd'")
        return
    }

    let (p, q) = try PrimeGenerator.calculatePrimeFactors(n: n, e: e, d: d)
    #expect(p * q == n, "The product of p and q should equal n; got \(p) * \(q) != \(n)")
}

struct TestGroup: Codable {
    let n: String
    let e: String
    let d: String
    let privateKeyJwk: PrivateKeyJWK?
}

struct PrivateKeyJWK: Codable {
    let kty: String
    let n: String
    let e: String
    let d: String
    let p: String
    let q: String
    let dp: String
    let dq: String
    let qi: String
}

struct TestVectors: Codable {
    let testGroups: [TestGroup]
}
