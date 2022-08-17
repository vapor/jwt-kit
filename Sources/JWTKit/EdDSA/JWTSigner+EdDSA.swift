import Foundation
import Crypto

extension JWTSigner {
	public static func eddsa<D: ContiguousBytes>(publicKey: D, privateKey: D?) -> JWTSigner {
		.init(
			algorithm: EdDSASigner(
				publicKey: publicKey,
				privateKey: privateKey
			)
		)
	}
}
