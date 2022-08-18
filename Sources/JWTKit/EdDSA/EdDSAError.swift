internal enum EdDSAError: Error {	
	case publicAndPrivateKeyMissing
	case privateKeyMissing
	case publicKeyMissing
	case curveNotSupported(JWK.Curve)
}
