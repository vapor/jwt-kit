import CryptoExtras

#if !canImport(Darwin)
public import FoundationEssentials
#else
public import Foundation
#endif

/// Namespace for the MLDSA (Module-Lattice-Based Digital Signature Algorithm) signing algorithm.
///
/// MLDSA is a post-quantum signature scheme based on the CRYSTALS-DILITHIUM algorithm and standardized
/// by NIST in [FIPS 204](https://nvlpubs.nist.gov/nistpubs/fips/nist.fips.204.pdf). Its use in JOSE,
/// and therefore in JWTs, is defined by [RFC 9964](https://datatracker.ietf.org/doc/rfc9964/).
///
/// Unlike the other algorithms supported by JWTKit, MLDSA keys are parameterised by the strength of the
/// parameter set they use, which is expressed by the ``MLDSAType`` generic parameter. JWTKit supports the
/// `MLDSA65` and `MLDSA87` parameter sets, which correspond to the `ML-DSA-65` and `ML-DSA-87`
/// JWS algorithms respectively.
@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
public enum MLDSA: Sendable {}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA {
    /// A struct representing a public key used in MLDSA (Module-Lattice-Based Digital Signature Algorithm).
    ///
    /// MLDSA public keys are used to verify signatures. The parameter set the key belongs to is expressed by
    /// the ``MLDSAType`` generic parameter, so a key is written as, for example, `MLDSA.PublicKey<MLDSA87>`.
    /// The ``MLDSA65PublicKey`` and ``MLDSA87PublicKey`` typealiases are provided as a shorthand.
    public struct PublicKey<KeyType>: MLDSAKey where KeyType: MLDSAType {
        /// The MLDSA parameter set this key belongs to.
        public typealias MLDSAType = KeyType

        typealias PublicKey = KeyType.PrivateKey.PublicKey

        let backing: any MLDSAPublicKey

        /// Creates an ``MLDSA/PublicKey`` instance using the provided public key.
        ///
        /// This init constructs an ``MLDSA/PublicKey`` based on the corresponding SwiftCrypto public key,
        /// such as `MLDSA65.PublicKey` or `MLDSA87.PublicKey`.
        ///
        /// - Parameter backing: The SwiftCrypto public key.
        public init(backing: some MLDSAPublicKey) {
            self.backing = backing
        }

        /// Creates an ``MLDSA/PublicKey`` instance using the provided raw byte representation.
        ///
        /// - Parameter rawRepresentation: The raw bytes of the public key. Its length must match the one
        ///   expected by the parameter set the key belongs to.
        ///
        /// - Throws: If the provided bytes aren't a valid public key for the key's parameter set.
        public init(rawRepresentation: some DataProtocol) throws {
            self.backing = try PublicKey(rawRepresentation: rawRepresentation)
        }
    }
}

@available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
extension MLDSA {
    /// A struct representing a private key used in MLDSA (Module-Lattice-Based Digital Signature Algorithm).
    ///
    /// MLDSA private keys are used to sign tokens. The parameter set the key belongs to is expressed by
    /// the ``MLDSAType`` generic parameter, so a key is written as, for example, `MLDSA.PrivateKey<MLDSA87>`.
    /// The ``MLDSA65PrivateKey`` and ``MLDSA87PrivateKey`` typealiases are provided as a shorthand.
    public struct PrivateKey<KeyType>: MLDSAKey where KeyType: MLDSAType {
        /// The MLDSA parameter set this key belongs to.
        public typealias MLDSAType = KeyType

        typealias PrivateKey = KeyType.PrivateKey

        let backing: any MLDSAPrivateKey

        /// The public key associated with this private key.
        public var publicKey: MLDSA.PublicKey<KeyType> {
            .init(backing: self.backing.publicKey)
        }

        /// Creates an ``MLDSA/PrivateKey`` instance using the provided private key.
        ///
        /// This init constructs an ``MLDSA/PrivateKey`` based on the corresponding SwiftCrypto private key,
        /// such as `MLDSA65.PrivateKey` or `MLDSA87.PrivateKey`.
        ///
        /// - Parameter backing: The SwiftCrypto private key.
        public init(backing: some MLDSAPrivateKey) {
            self.backing = backing
        }

        /// Creates an ``MLDSA/PrivateKey`` instance using the seed it is derived from.
        ///
        /// MLDSA private keys are stored and transmitted as the 32-byte seed they are derived from, rather
        /// than as the expanded key itself. The key is derived from the seed following the
        /// `ML-DSA.KeyGen_internal` algorithm of FIPS 204.
        ///
        /// - Parameters:
        ///   - seedRepresentation: The 32-byte seed the private key is derived from.
        ///   - publicKey: An optional public key to check the derived key against. When provided, a consistency
        ///     check is performed between it and the public key derived from the seed.
        ///
        /// - Throws: If the seed isn't valid for the key's parameter set, or if the provided public key doesn't
        ///   match the one derived from the seed.
        public init(seedRepresentation: some DataProtocol, publicKey: KeyType.PrivateKey.PublicKey? = nil) throws {
            self.backing = try PrivateKey(seedRepresentation: seedRepresentation, publicKey: publicKey)
        }
    }
}
