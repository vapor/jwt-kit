import Foundation
import Crypto

public struct EdDSAKey {
			
	let keyPair: OctetKeyPair
	var publicKey: Data? {
		keyPair.publicKey
	}
	var privateKey: Data? {
		keyPair.privateKey
	}
	let curve: JWK.Curve
	
	public init(x: String?, d: String? = nil, curve: JWK.Curve = .ed25519) throws {
		try self.init(
			publicKey: x.flatMap { $0.data(using: .utf8) }.map { Data($0.base64URLDecodedBytes()) },
			privateKey: d.flatMap { $0.data(using: .utf8) }.map { Data($0.base64URLDecodedBytes()) },
			curve: curve
		)
	}
	
	public init(publicKey: Data? = nil, privateKey: Data? = nil, curve: JWK.Curve = .ed25519) throws {
		try self.init(
			keyPair: try .init(publicKey: publicKey, privateKey: privateKey),
			curve: curve
		)
	}
	
	init(keyPair: OctetKeyPair, curve: JWK.Curve = .ed25519) throws {
		guard curve == .ed25519 else {
			throw JWTError.signingAlgorithmFailure(EdDSAError.curveNotSupported(curve))
		}
		self.keyPair = keyPair
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

