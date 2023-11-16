import XCTest

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
