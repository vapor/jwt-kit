internal enum EdDSAError: Error {	
	case privateKeyMissing
	case curveNotSupported(JWK.Curve)
	case publicKeyMissing
}
