#if !canImport(Darwin)
public import FoundationEssentials
#else
public import Foundation
#endif

/// A protocol defining the necessary functionality for a JWT (JSON Web Token) algorithm.
/// All algorithms conform to ``JWTAlgorithm`` to provide custom signing and verification logic for JWT tokens.
public protocol JWTAlgorithm: Sendable {
    /// Unique JWT-standard name for this algorithm.
    var name: String { get }

    /// Creates a signature from the supplied plaintext.
    ///
    ///     let sig = try alg.sign("hello")
    ///
    /// - parameters:
    ///     - plaintext: Plaintext data to sign.
    /// - returns: Signature unique to the supplied data.
    func sign(_ plaintext: some DataProtocol) throws -> [UInt8]

    /// Returns `true` if the signature was creating by signing the plaintext.
    ///
    ///     let sig = try alg.sign("hello")
    ///
    ///     if alg.verify(sig, signs: "hello") {
    ///         print("signature is valid")
    ///     } else {
    ///         print("signature is invalid")
    ///     }
    ///
    /// The above snippet should print `"signature is valid"`.
    ///
    /// - parameters:
    ///     - signature: Signature data resulting from a previous call to `sign(:_)`.
    ///     - plaintext: Plaintext data to check signature against.
    /// - returns: Returns `true` if the signature was created by the supplied plaintext data.
    func verify(_ signature: some DataProtocol, signs plaintext: some DataProtocol) throws -> Bool
}

extension JWTAlgorithm {
    /// See ``JWTAlgorithm``.
    func verify(_ signature: some DataProtocol, signs plaintext: some DataProtocol) throws -> Bool {
        let check = try sign(plaintext)
        let candidate = Array(signature)

        guard check.count == candidate.count else { return false }

        // Accumulate the differences to ensure we always run in constant time
        var difference: UInt8 = 0
        for (a, b) in zip(check, candidate) {
            difference |= a ^ b
        }
        return difference == 0
    }
}
