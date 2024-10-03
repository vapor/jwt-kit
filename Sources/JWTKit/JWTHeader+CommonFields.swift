extension JWTHeader {
    /// The `alg` (Algorithm) Header Parameter identifies the cryptographic algorithm used to secure the JWT.
    /// Common values include `HS256`, `RS256`, etc.
    public var alg: String? {
        get { self[dynamicMember: "alg"]?.asString }
        set { self[dynamicMember: "alg"] = newValue.map { .string($0) } }
    }

    /// The `kid` (Key ID) Header Parameter is a hint indicating which key was used to secure the JWT.
    /// This parameter allows originators to explicitly signal a change of key to recipients.
    public var kid: String? {
        get { self[dynamicMember: "kid"]?.asString }
        set { self[dynamicMember: "kid"] = newValue.map { .string($0) } }
    }

    /// The `typ` (Type) Header Parameter is used to declare the media type of the JWT.
    /// While optional, it's typically set to `JWT`.
    public var typ: String? {
        get { self[dynamicMember: "typ"]?.asString }
        set { self[dynamicMember: "typ"] = newValue.map { .string($0) } }
    }

    /// The `cty` (Content Type) Header Parameter is used to declare the media type of the payload
    /// when the JWT is nested (e.g., encrypted JWT inside a JWT).
    public var cty: String? {
        get { self[dynamicMember: "cty"]?.asString }
        set { self[dynamicMember: "cty"] = newValue.map { .string($0) } }
    }

    /// The `crit` (Critical) Header Parameter indicates that extensions to standard JWT specifications
    /// are being used and must be understood and processed.
    public var crit: [String]? {
        get {
            if case .array(let array) = self[dynamicMember: "crit"] {
                return array.compactMap { $0.asString }
            }
            return nil
        }
        set {
            let arrayField = newValue?.map { JWTHeaderField.string($0) }
            self[dynamicMember: "crit"] = arrayField.map { .array($0) }
        }
    }

    /// The `jku` (JWK Set URL) Header Parameter is a URI that refers to a resource for a set of JSON-encoded public keys,
    /// one of which corresponds to the key used to digitally sign the JWT.
    public var jku: String? {
        get { self[dynamicMember: "jku"]?.asString }
        set { self[dynamicMember: "jku"] = newValue.map { .string($0) } }
    }

    /// The `jwk` (JSON Web Key) Header Parameter is a JSON object that represents a cryptographic key.
    /// This parameter is used to transmit a key to be used in securing the JWT.
    public var jwk: [String: JWTHeaderField]? {
        get { self[dynamicMember: "jwk"]?.asObject }
        set { self[dynamicMember: "jwk"] = newValue.map { .object($0) } }
    }

    /// The `x5c` (X.509 Certificate Chain) Header Parameter contains a chain of one or more PKIX certificates.
    /// Each string in the array is a base64-encoded (Section 4 of [RFC4648] - not base64url-encoded) DER [ITU.X690.1994] PKIX certificate value.
    public var x5c: [String]? {
        get {
            if case .array(let array) = self[dynamicMember: "x5c"] {
                return array.compactMap { $0.asString }
            }
            return nil
        }
        set {
            let arrayField = newValue?.map { JWTHeaderField.string($0) }
            self[dynamicMember: "x5c"] = arrayField.map { .array($0) }
        }
    }

    /// The `x5u` (X.509 URL) Header Parameter is a URI that refers to a resource for the X.509 public key certificate
    /// or certificate chain corresponding to the key used to digitally sign the JWT.
    public var x5u: String? {
        get { self[dynamicMember: "x5u"]?.asString }
        set { self[dynamicMember: "x5u"] = newValue.map { .string($0) } }
    }

    /// The `x5t` (X.509 Certificate SHA-1 Thumbprint) Header Parameter is a base64url-encoded SHA-1 thumbprint
    /// (a.k.a. digest) of the DER encoding of the X.509 certificate [RFC5280].
    public var x5t: String? {
        get { self[dynamicMember: "x5t"]?.asString }
        set { self[dynamicMember: "x5t"] = newValue.map { .string($0) } }
    }

    /// The `x5t#S256` (X.509 Certificate SHA-256 Thumbprint) Header Parameter is a base64url-encoded SHA-256 thumbprint
    /// of the DER encoding of the X.509 certificate [RFC5280].
    public var x5tS256: String? {
        get { self[dynamicMember: "x5t#S256"]?.asString }
        set { self[dynamicMember: "x5t#S256"] = newValue.map { .string($0) } }
    }
}
