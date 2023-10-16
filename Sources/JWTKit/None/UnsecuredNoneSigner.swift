import Foundation

internal struct UnsecuredNoneSigner: JWTAlgorithm {
    var name: String {
        "none"
    }
    
    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        []
    }
    
    func verify<Signature, Plaintext>(_ signature: Signature, signs plaintext: Plaintext) throws -> Bool
        where Signature: DataProtocol, Plaintext: DataProtocol
    {
        signature.isEmpty
    }
}
