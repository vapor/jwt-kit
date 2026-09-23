/// The three segments of a compact-serialised JWT, as views into the original token bytes.
///
/// Nothing is copied: each part is a slice of `token`, and ``signingInput`` (`header.payload`)
/// is the prefix of the token up to the second period, which is what the signature covers.
struct TokenParts {
    let token: [UInt8]
    private let firstPeriod: Int
    private let secondPeriod: Int

    init(_ token: [UInt8]) throws {
        guard let firstPeriod = token.firstIndex(of: .period),
            let secondPeriod = token[(firstPeriod + 1)...].firstIndex(of: .period),
            !token[(secondPeriod + 1)...].contains(.period)
        else {
            throw JWTError.malformedToken(reason: "Token is not split in 3 parts")
        }
        self.token = token
        self.firstPeriod = firstPeriod
        self.secondPeriod = secondPeriod
    }

    var header: ArraySlice<UInt8> { token[..<firstPeriod] }
    var payload: ArraySlice<UInt8> { token[(firstPeriod + 1)..<secondPeriod] }
    var signature: ArraySlice<UInt8> { token[(secondPeriod + 1)...] }
    var signingInput: ArraySlice<UInt8> { token[..<secondPeriod] }
}
