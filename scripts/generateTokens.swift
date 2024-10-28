/// This script can be used to regenerate the X5CTests tokens
/// when they don't verify anymore. If you're here, it likely means
/// the certificates are expired and should be updated.
/// This script does just that: generate new certificates and create
/// tokens with x5c chains based on those certs.
///
/// To run the script, simply run `swift scripts/generateTokens.swift`.
/// The output will be
///   - the new tokens, printed in Swift, which means you
///     just need to copy and paste them replacing the old ones;
///   - the root certificate, which you have to replace too.
/// After creating the tokens, the script will delete certificates.
/// If you want to keep them for some reason, just add `--keep-certs`
/// to the script execution. They will be stored in the `x5c_test_certs`.
/// This directory is in the `.gitignore` so that it doesn't get committed.
import Foundation

enum ScriptError: Error {
    case certificateGenerationFailed(status: Int32)
    case fileNotFound(at: String)
    case invalidSignature(String)
}

struct JWTGenerator {
    let certificateDirectory = "x5c_test_certs"
    let leafKeyFileName = "leaf_key.pem"
    let leafCertFileName = "leaf_cert.pem"
    let expiredLeafCertFileName = "expired_leaf_cert.pem"
    let intermediateCertFileName = "intermediate_cert.pem"
    let rootCertFileName = "root_cert.pem"

    func generateCertificates() throws {
        let process = Process()
        process.launchPath = "/bin/bash"
        process.arguments = ["scripts/generate-certificates.sh"]

        try process.run()
        process.waitUntilExit()

        if process.terminationStatus != 0 {
            throw ScriptError.certificateGenerationFailed(status: process.terminationStatus)
        }

        print("✅ Certificates generated successfully")
    }

    func readCertificateData(from name: String, stripped: Bool = true) throws -> String {
        let path = URL(filePath: certificateDirectory).appending(path: name)
        let content = try String(contentsOf: path, encoding: .utf8)
        let finalContent =
            if stripped {
                content
                    .replacing("-----BEGIN CERTIFICATE-----", with: "")
                    .replacing("-----END CERTIFICATE-----", with: "")
                    .replacing("\n", with: "")
            } else {
                content
            }
        return finalContent
    }

    func generateToken(payload: [String: Any], certificates: [String], signingKeyPath: String) throws -> String {
        func base64URLEncode(_ data: Data) -> String {
            data.base64EncodedString()
                .replacingOccurrences(of: "+", with: "-")
                .replacingOccurrences(of: "/", with: "_")
                .replacingOccurrences(of: "=", with: "")
        }

        let x5cChain = try certificates.map { try readCertificateData(from: $0) }

        let header: [String: Any] = [
            "alg": "ES256",
            "typ": "JWT",
            "x5c": x5cChain,
        ]
        let encodedHeader = try base64URLEncode(JSONSerialization.data(withJSONObject: header))
        let encodedBody = try base64URLEncode(JSONSerialization.data(withJSONObject: payload))

        let message = "\(encodedHeader).\(encodedBody)"

        let task = Process()
        task.executableURL = URL(filePath: "/bin/bash")
        let command = """
            echo -n "\(message)" | 
            openssl dgst -sha256 -sign "\(certificateDirectory)/\(signingKeyPath)" | 
            openssl asn1parse -inform DER |
            perl -n -e '/INTEGER           :([0-9A-Z]*)$/ && print $1' |
            xxd -p -r
            """
        task.arguments = ["-c", command]

        let outputPipe = Pipe()
        task.standardOutput = outputPipe

        try task.run()
        let signature = base64URLEncode(outputPipe.fileHandleForReading.readDataToEndOfFile())
        return "\(message).\(signature)"
    }

    func generateTokens(keepingCertificates: Bool = false) throws {
        let coolPayload = ["cool": true]
        let tokens = try [
            "validToken": generateToken(
                payload: coolPayload, certificates: [leafCertFileName, intermediateCertFileName, rootCertFileName],
                signingKeyPath: leafKeyFileName
            ),
            "missingIntermediateToken": generateToken(
                payload: coolPayload, certificates: [leafCertFileName, rootCertFileName], signingKeyPath: leafKeyFileName
            ),
            "missingRootToken": generateToken(
                payload: coolPayload, certificates: [leafCertFileName, intermediateCertFileName], signingKeyPath: leafKeyFileName
            ),
            "missingLeafToken": generateToken(
                payload: coolPayload, certificates: [intermediateCertFileName, rootCertFileName], signingKeyPath: leafKeyFileName
            ),
            "missingLeafAndIntermediateToken": generateToken(
                payload: coolPayload, certificates: [rootCertFileName], signingKeyPath: leafKeyFileName
            ),
            "missingIntermediateAndRootToken": generateToken(
                payload: coolPayload, certificates: [leafCertFileName], signingKeyPath: leafKeyFileName
            ),
            "expiredLeafToken": generateToken(
                payload: coolPayload, certificates: [expiredLeafCertFileName, intermediateCertFileName, rootCertFileName],
                signingKeyPath: leafKeyFileName
            ),
            "validButNotCoolToken": generateToken(
                payload: ["cool": false], certificates: [leafCertFileName, intermediateCertFileName, rootCertFileName],
                signingKeyPath: leafKeyFileName
            ),
        ]
        print("Swift Token Declarations:")
        for (name, token) in tokens {
            print(
                """
                let \(name) = \"""
                    \(token)
                    \"""
                """)
        }
        try print(readCertificateData(from: rootCertFileName, stripped: false))

        if !keepingCertificates {
            try? FileManager.default.removeItem(atPath: certificateDirectory)
            print("🧹 Certificates cleaned up")
        } else {
            if let absolutePath = FileManager.default.currentDirectoryPath as NSString? {
                print("💾 Certificates saved in \(absolutePath.appendingPathComponent(certificateDirectory))")
            }
        }
    }
}

let generator = JWTGenerator()
let keepingCertificates = CommandLine.arguments.contains("--keep-certs")
do {
    try generator.generateCertificates()
    try generator.generateTokens(keepingCertificates: keepingCertificates)
} catch {
    print("Error: \(error)")
    exit(1)
}
