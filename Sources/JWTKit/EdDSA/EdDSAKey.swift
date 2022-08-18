import Foundation
import Crypto

public struct EdDSAKey {
	
	let publicKey: Data
	let privateKey: Data?
	let curve: JWK.Curve
	
	public init(x: String, d: String? = nil, curve: JWK.Curve = .ed25519) throws {
				
		guard let x = x.data(using: .utf8) else {
			throw JWTError.signingAlgorithmFailure(EdDSAError.publicKeyMissing)
		}
		
		try self.init(
			publicKey: Data(x.base64URLDecodedBytes()),
			privateKey: d.flatMap { $0.data(using: .utf8) }.map { Data($0.base64URLDecodedBytes()) },
			curve: curve
		)
	}
	
	public init(publicKey: Data, privateKey: Data? = nil, curve: JWK.Curve = .ed25519) throws {
		guard curve == .ed25519 else {
			throw JWTError.signingAlgorithmFailure(EdDSAError.curveNotSupported(curve))
		}
				
		self.publicKey = publicKey
		self.privateKey = privateKey
		self.curve = curve
	}
	
	public static func generate(curve: JWK.Curve = .ed25519) throws -> EdDSAKey {
		guard curve == .ed25519 else {
			throw JWTError.signingAlgorithmFailure(EdDSAError.curveNotSupported(curve))
		}
		
		let key = Curve25519.Signing.PrivateKey()
		return try .init(
			publicKey: key.publicKey.rawRepresentation,
			privateKey: key.rawRepresentation,
			curve: curve
		)
	}
}

