@_implementationOnly import CJWTKitBoringSSL
import struct Foundation.Data


/// The extension for retrieving the subject of RSAKey.
///
/// For more information about syntax for RSA keys,
/// see https://datatracker.ietf.org/doc/html/rfc3447#appendix-A
public extension RSAKey {
    
    /// version is the version number.
    /// Always be 0, since the version 1 is not supported for now.
    var version: Int {
        return 0
    }
    
    /// modulus is the RSA modulus n.
    var modulus: Data? {
        guard let m_bn = CJWTKitBoringSSL_RSA_get0_n(self.c) else {
            return nil
        }
        return m_bn.toData()
    }
    
    
    /// publicExponent is the RSA public exponent e.
    var publicExponent: Data? {
        guard let e_bn = CJWTKitBoringSSL_RSA_get0_e(self.c) else {
            return nil
        }
        return e_bn.toData()
    }
    
    /// privateExponent is the RSA private exponent d.
    var privateExponent: Data? {
        guard let d_bn = CJWTKitBoringSSL_RSA_get0_d(self.c) else {
            return nil
        }
        return d_bn.toData()
    }

    /// prime1 is the prime factor p of n.
    var prime1: Data? {
        guard let d_bn = CJWTKitBoringSSL_RSA_get0_p(self.c) else {
            return nil
        }
        return d_bn.toData()
    }

    /// prime2 is the prime factor q of n.
    var prime2: Data? {
        guard let d_bn = CJWTKitBoringSSL_RSA_get0_q(self.c) else {
            return nil
        }
        return d_bn.toData()
    }

    /// exponent1 is d mod (p - 1).
    var exponent1: Data? {
        guard let exponent1_bn = CJWTKitBoringSSL_RSA_get0_dmp1(self.c) else {
            return nil
        }
        return exponent1_bn.toData()
    }

    /// exponent2 is d mod (q - 1).
    var exponent2: Data? {
        guard let exponent2_bn = CJWTKitBoringSSL_RSA_get0_dmq1(self.c) else {
            return nil
        }
        return exponent2_bn.toData()
    }

    // coefficient is the CRT coefficient q^(-1) mod p.
    var coefficient: Data? {
        guard let coefficient_bn = CJWTKitBoringSSL_RSA_get0_iqmp(self.c) else {
            return nil
        }
        return coefficient_bn.toData()
    }
}
