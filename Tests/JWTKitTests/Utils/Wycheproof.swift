import Foundation
import XCTest

func wycheproof(fileName: String, testFunction: (TestGroup) throws -> Void) throws {
    let testsDirectory: String = URL(fileURLWithPath: "\(#filePath)").pathComponents.dropLast(2).joined(separator: "/")
    let url = URL(fileURLWithPath: "\(testsDirectory)/TestVectors/\(fileName).json")
    guard let data = try? Data(contentsOf: url) else {
        return XCTFail("Failed to load Wycheproof test vectors from file \(fileName).json")
    }

    let testVectors = try JSONDecoder().decode(TestVectors.self, from: data)

    for testGroup in testVectors.testGroups {
        try testFunction(testGroup)
    }
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
