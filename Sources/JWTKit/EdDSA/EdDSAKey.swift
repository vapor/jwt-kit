import Foundation

public struct EdDSAKey {
	
	let publicKey: Data
	let privateKey: Data?
	let curve: JWK.Curve
	
	public init?(x: String, d: String? = nil, curve: JWK.Curve = .ed25519) {
		guard let x = Data(base64Encoded: x.base64UrlEncodedToBase64()) else {
			return nil
		}
		
		self.init(
			publicKey: x,
			privateKey: d.flatMap { Data(base64Encoded: $0.base64UrlEncodedToBase64()) },
			curve: curve
		)
	}
	
	public init(publicKey: Data, privateKey: Data? = nil, curve: JWK.Curve = .ed25519) {
		self.publicKey = publicKey
		self.privateKey = privateKey
		self.curve = curve
	}
}

extension String {
	func base64UrlEncodedToBase64() -> String {
		var base64 = replacingOccurrences(of: "-", with: "+").replacingOccurrences(of: "_", with: "/")
		if base64.count % 4 != 0 {
			base64.append(
				String(repeating: "=", count: 4 - base64.count % 4)
			)
		}
		return base64
	}
}
