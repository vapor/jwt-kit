import Foundation
import SwiftASN1

extension Insecure.RSA.PrivateKey {
    /// From [RFC 8017 § A.1.2](https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1.2):
    ///
    /// ```
    /// RSAPrivateKey ::= SEQUENCE {
    ///     version           Version,
    ///     modulus           INTEGER,  -- n
    ///     publicExponent    INTEGER,  -- e
    ///     privateExponent   INTEGER,  -- d
    ///     prime1            INTEGER,  -- p
    ///     prime2            INTEGER,  -- q
    ///     exponent1         INTEGER,  -- d mod (p-1)
    ///     exponent2         INTEGER,  -- d mod (q-1)
    ///     coefficient       INTEGER,  -- (inverse of q) mod p
    ///     otherPrimeInfos   OtherPrimeInfos OPTIONAL
    /// }
    /// ```
    struct ASN1: DERSerializable {
        let version: UInt8
        let modulus: ArraySlice<UInt8>
        let publicExponent: ArraySlice<UInt8>
        let privateExponent: ArraySlice<UInt8>
        let prime1: ArraySlice<UInt8>
        let prime2: ArraySlice<UInt8>
        let exponent1: ArraySlice<UInt8>
        let exponent2: ArraySlice<UInt8>
        let coefficient: ArraySlice<UInt8>

        init(
            version: UInt8 = 0,
            modulus: ArraySlice<UInt8>,
            publicExponent: ArraySlice<UInt8>,
            privateExponent: ArraySlice<UInt8>,
            prime1: ArraySlice<UInt8>,
            prime2: ArraySlice<UInt8>,
            exponent1: ArraySlice<UInt8>,
            exponent2: ArraySlice<UInt8>,
            coefficient: ArraySlice<UInt8>
        ) {
            self.version = version
            self.modulus = modulus
            self.publicExponent = publicExponent
            self.privateExponent = privateExponent
            self.prime1 = prime1
            self.prime2 = prime2
            self.exponent1 = exponent1
            self.exponent2 = exponent2
            self.coefficient = coefficient
        }
    }

    /// Retrieves the RSA private key primitives.
    ///
    /// This function extracts the modulus, public exponent, and private exponent from an RSA private key.
    ///
    /// - Returns: A tuple containing the modulus, public exponent, and private exponent as Base64 URL-encoded strings.
    /// - Throws: ``JWTError`` if the key is not a private RSA key or if there is an issue parsing the key.
    public func getKeyPrimitives() throws -> (modulus: String, exponent: String, privateExponent: String) {
        let parsed = try DER.parse(Array(self.derRepresentation))
        let rsaPrivateKey = try ASN1(derEncoded: parsed)

        let modulus = String(decoding: Data(rsaPrivateKey.modulus).base64URLEncodedBytes(), as: UTF8.self)
        let publicExponent = String(decoding: Data(rsaPrivateKey.publicExponent).base64URLEncodedBytes(), as: UTF8.self)
        let privateExponent = String(decoding: Data(rsaPrivateKey.privateExponent).base64URLEncodedBytes(), as: UTF8.self)

        return (modulus, publicExponent, privateExponent)
    }
}

extension Insecure.RSA.PrivateKey.ASN1: DERImplicitlyTaggable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    init(derEncoded: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(derEncoded, identifier: identifier) { nodes in
            let version = try UInt8(derEncoded: &nodes)
            guard version == 0 else {
                throw ASN1Error.invalidASN1Object(reason: "Invalid version")
            }

            let modulus = try ArraySlice(derEncoded: &nodes)
            let publicExponent = try ArraySlice<UInt8>(derEncoded: &nodes)
            let privateExponent = try ArraySlice<UInt8>(derEncoded: &nodes)
            let prime1 = try ArraySlice<UInt8>(derEncoded: &nodes)
            let prime2 = try ArraySlice<UInt8>(derEncoded: &nodes)
            let exponent1 = try ArraySlice<UInt8>(derEncoded: &nodes)
            let exponent2 = try ArraySlice<UInt8>(derEncoded: &nodes)
            let coefficient = try ArraySlice<UInt8>(derEncoded: &nodes)

            return .init(
                modulus: modulus,
                publicExponent: publicExponent,
                privateExponent: privateExponent,
                prime1: prime1,
                prime2: prime2,
                exponent1: exponent1,
                exponent2: exponent2,
                coefficient: coefficient
            )
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.version)
            try coder.serialize(self.modulus)
            try coder.serialize(self.publicExponent)
            try coder.serialize(self.privateExponent)
            try coder.serialize(self.prime1)
            try coder.serialize(self.prime2)
            try coder.serialize(self.exponent1)
            try coder.serialize(self.exponent2)
            try coder.serialize(self.coefficient)
        }
    }
}
