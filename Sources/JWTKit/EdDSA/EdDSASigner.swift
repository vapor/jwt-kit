import Crypto

internal struct EdDSASigner<D: ContiguousBytes>: JWTAlgorithm {
	let publicKey: D
	let privateKey: D
	let name = "EdDSA"
	
	func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8] where Plaintext : DataProtocol {
		try Curve25519.Signing.PrivateKey(
			rawRepresentation: privateKey
		).signature(
			for: plaintext
		).copyBytes()
	}
	
	func verify<Signature, Plaintext>(_ signature: Signature, signs plaintext: Plaintext) throws -> Bool where Signature : DataProtocol, Plaintext : DataProtocol {
				
		try Curve25519.Signing.PublicKey(
			rawRepresentation: publicKey
		).isValidSignature(
			signature,
			for: plaintext
		)
	}
}
