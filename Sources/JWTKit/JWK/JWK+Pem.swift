public extension JWK {
    static func rsa(
        _ key: RSAKey?,
        _ algorithm: Algorithm?,
        identifier: JWKIdentifier?
    ) -> JWK {
        JWK.rsa(
            algorithm,
            identifier: identifier,
            modulus: key?.modulus?.base64URLEncodedString(),
            exponent: key?.publicExponent?.base64URLEncodedString()
        )
    }
}
