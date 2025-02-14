#if !canImport(Darwin)
import FoundationEssentials
#else
import Foundation
#endif

struct UnsecuredNoneSigner: JWTAlgorithm {
    var name: String {
        "none"
    }

    func sign(_: some DataProtocol) throws -> [UInt8] {
        []
    }

    func verify(_ signature: some DataProtocol, signs _: some DataProtocol) throws -> Bool {
        signature.isEmpty
    }
}
