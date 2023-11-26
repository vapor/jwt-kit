import Foundation
import SwiftASN1

extension RSA.PublicKey {
    /// From [RFC 8017 § A.1.2](https://www.rfc-editor.org/rfc/rfc8017#appendix-A.1.1):
    ///
    /// ```
    /// RSAPublicKey ::= SEQUENCE {
    ///     modulus           INTEGER,  -- n
    ///     publicExponent    INTEGER   -- e
    /// }
    /// ```
    struct ASN1: DERSerializable {
        let modulus: ArraySlice<UInt8>
        let publicExponent: ArraySlice<UInt8>

        init(modulus: ArraySlice<UInt8>, publicExponent: ArraySlice<UInt8>) {
            self.modulus = modulus
            self.publicExponent = publicExponent
        }
    }

    /// Retrieves the RSA public key primitives.
    ///
    /// This function extracts the modulus and public exponent from an RSA private key.
    ///
    /// - Returns: A tuple containing the modulus and public exponent as Base64 URL-encoded strings.
    /// - Throws: If there is an issue parsing the key.
    public func getKeyPrimitives() throws -> (modulus: String, exponent: String) {
        let parsed = try DER.parse(Array(self.derRepresentation))
        let spki = try SubjectPublicKeyInfo(derEncoded: parsed)
        let parsedKey = try DER.parse(spki.key.bytes)
        let rsaPublicKey = try ASN1(derEncoded: parsedKey)

        let modulus = String(decoding: Data(rsaPublicKey.modulus).base64URLEncodedBytes(), as: UTF8.self)
        let exponent = String(decoding: Data(rsaPublicKey.publicExponent).base64URLEncodedBytes(), as: UTF8.self)

        return (modulus, exponent)
    }
}

extension RSA.PublicKey.ASN1: DERImplicitlyTaggable {
    static var defaultIdentifier: SwiftASN1.ASN1Identifier {
        .sequence
    }

    init(derEncoded rootNode: SwiftASN1.ASN1Node, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let modulus = try ArraySlice(derEncoded: &nodes)
            let publicExponent = try ArraySlice<UInt8>(derEncoded: &nodes)

            return .init(modulus: modulus, publicExponent: publicExponent)
        }
    }

    func serialize(into coder: inout SwiftASN1.DER.Serializer, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.modulus)
            try coder.serialize(self.publicExponent)
        }
    }
}
