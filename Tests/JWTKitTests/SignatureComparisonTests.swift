import Foundation
import JWTKit
import Testing

@Suite("Signature comparison")
struct SignatureComparisonTests {
    struct Payload: JWTPayload, Equatable {
        var sub: String
        func verify(using _: some JWTAlgorithm) throws {}
    }

    static func keys(_ digest: DigestAlgorithm) async -> JWTKeyCollection {
        switch digest {
        case .sha256:
            await JWTKeyCollection().add(hmac: "a-string-secret-at-least-256-bits-long", digestAlgorithm: digest)
        case .sha384:
            await JWTKeyCollection().add(hmac: "a-valid-string-secret-that-is-at-least-384-bits-long", digestAlgorithm: digest)
        case .sha512:
            await JWTKeyCollection().add(
                hmac: "a-valid-string-secret-that-is-at-least-512-bits-long-which-is-very-long", digestAlgorithm: digest)
        default: fatalError()
        }
    }

    @Test("Valid signatures verify", arguments: [DigestAlgorithm.sha256, .sha384, .sha512])
    func validSignatureVerifies(_ digest: DigestAlgorithm) async throws {
        let keys = await Self.keys(digest)
        let payload = Payload(sub: "1234567890")
        let token = try await keys.sign(payload)
        #expect(try await keys.verify(token, as: Payload.self) == payload)
    }

    @Test("A single flipped bit in the signature is rejected", arguments: [DigestAlgorithm.sha256, .sha512])
    func flippedBitIsRejected(_ digest: DigestAlgorithm) async throws {
        let keys = await Self.keys(digest)
        let token = try await keys.sign(Payload(sub: "1234567890"))
        var parts = token.split(separator: ".").map(String.init)

        // Flip the first character of the signature to something else in the alphabet.
        // The first character is used because the last one may be a padding character
        // that doesn't decode to any data, so verification would succeed.
        let first = parts[2].removeFirst()
        parts[2].insert(first == "A" ? "B" : "A", at: parts[2].startIndex)

        await #expect(throws: JWTError.signatureVerificationFailed) {
            _ = try await keys.verify(parts.joined(separator: "."), as: Payload.self)
        }
    }

    @Test("Truncated, extended and empty signatures are rejected")
    func lengthMismatchesRejected() async throws {
        let keys = await Self.keys(.sha256)
        let token = try await keys.sign(Payload(sub: "1234567890"))
        let parts = token.split(separator: ".").map(String.init)

        for signature in ["", String(parts[2].dropLast(4)), parts[2] + "AAAA"] {
            await #expect(throws: (any Error).self) {
                _ = try await keys.verify("\(parts[0]).\(parts[1]).\(signature)", as: Payload.self)
            }
        }
    }

    @Test("Signatures do not verify under the wrong key or digest")
    func wrongKeyOrDigestRejected() async throws {
        let token = try await Self.keys(.sha256).sign(Payload(sub: "1234567890"))

        let otherSecret = await JWTKeyCollection().add(hmac: "another-string-secret-at-least-256-bits-long", digestAlgorithm: .sha256)
        await #expect(throws: (any Error).self) {
            _ = try await otherSecret.verify(token, as: Payload.self)
        }

        let otherDigest = await Self.keys(.sha512)
        await #expect(throws: (any Error).self) {
            _ = try await otherDigest.verify(token, as: Payload.self)
        }
    }
}
