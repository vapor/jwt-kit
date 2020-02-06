import CJWTKitCrypto
import Crypto
import Foundation

extension JWTSigner {
    // MARK: HMAC

    public static func hs256<Key>(key: Key) -> JWTSigner
        where Key: DataProtocol
    {
        return .init(algorithm: HMACSigner<SHA256>(
            key: key.copyBytes(),
            name: "HS256"
        ))
    }
    
    public static func hs384<Key>(key: Key) -> JWTSigner
        where Key: DataProtocol
    {
        return .init(algorithm: HMACSigner<SHA384>(
            key: key.copyBytes(),
            name: "HS384"
        ))
    }
    
    public static func hs512<Key>(key: Key) -> JWTSigner
        where Key: DataProtocol
    {
//        return .init(algorithm: HMACSigner(
//            key: key.copyBytes(),
//            algorithm: convert(EVP_sha512()),
//            name: "HS512"
//        ))
        return .init(algorithm: HMACSigner<SHA512>(key: key.copyBytes(), name: "HS512"))
    }
}

// MARK: Private

private enum HMACError: Error {
    case initializationFailure
    case updateFailure
    case finalizationFailure
}

private struct HMACSigner<SHA_TYPE>: JWTAlgorithm where SHA_TYPE: HashFunction {
    #warning("Key should probably be a Cyrpto key")
    let key: [UInt8]
    let name: String
    
    func sign<Plaintext>(_ plaintext: Plaintext) throws -> [UInt8]
        where Plaintext: DataProtocol
    {
        let key = SymmetricKey(data: self.key)
        let authentication = Crypto.HMAC<SHA_TYPE>.authenticationCode(for: plaintext, using: key)
        #warning("Change return type to Data")
        return Data(authentication).copyBytes()
    }
}
