import Crypto

internal struct EdDSASigner: JWTAlgorithm {
	let key: EdDSAKey
	let name = "EdDSA"
	
	func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8] where Plaintext : DataProtocol {
		
		guard key.curve == .ed25519 else {
			throw  JWTError.signingAlgorithmFailure(EdDSAError.curveNotSupported(key.curve))
		}
		
		guard let privateKey = key.privateKey else {
			throw  JWTError.signingAlgorithmFailure(EdDSAError.privateKeyMissing)
		}
		
		return try Curve25519.Signing.PrivateKey(
			rawRepresentation: privateKey
		).signature(
			for: plaintext
		).copyBytes()
	}
	
	func verify<Signature, Plaintext>(_ signature: Signature, signs plaintext: Plaintext) throws -> Bool where Signature : DataProtocol, Plaintext : DataProtocol {
		
		guard key.curve == .ed25519 else {
			throw  JWTError.signingAlgorithmFailure(EdDSAError.curveNotSupported(key.curve))
		}
		
		guard let publicKey = key.publicKey else {
			throw  JWTError.signingAlgorithmFailure(EdDSAError.publicKeyMissing)
		}
		
		return try Curve25519.Signing.PublicKey(
			rawRepresentation: publicKey
		).isValidSignature(
			signature,
			for: plaintext
		)
	}
}
