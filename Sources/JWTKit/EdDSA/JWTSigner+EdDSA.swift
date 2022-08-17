import Foundation
import Crypto

extension JWTSigner {
	public static func eddsa(publicKey: Data, privateKey: Data) -> JWTSigner {
		.init(
			algorithm: EdDSASigner(
				publicKey: publicKey,
				privateKey: privateKey
			)
		)
	}
}
