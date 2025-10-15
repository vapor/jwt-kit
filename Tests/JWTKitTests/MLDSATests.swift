import Crypto
import Foundation
@_spi(PostQuantum) import JWTKit
import Testing

@Suite("MLDSA Tests")
struct MLDSATests {
    @Test("MLDSA65 Signing")
    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
    func sign65() async throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: some JWTAlgorithm) throws {}
        }

        let key = try MLDSA65PrivateKey(
            seedRepresentation: Data(fromHexEncodedString: mldsa65PrivateKeySeedRepresentation)!)

        let keyCollection = JWTKeyCollection()
        await keyCollection.add(mldsa: key)

        let jwt = try await keyCollection.sign(Foo(bar: 42))
        let verified = try await keyCollection.verify(jwt, as: Foo.self)

        #expect(verified.bar == 42)
    }

    @Test("MLDSA87 Signing")
    @available(iOS 26.0, macOS 26.0, watchOS 26.0, tvOS 26.0, *)
    func sign87() async throws {
        struct Foo: JWTPayload {
            var bar: Int
            func verify(using _: some JWTAlgorithm) throws {}
        }

        let key = try MLDSA87PrivateKey(
            seedRepresentation: Data(fromHexEncodedString: mldsa87PrivateKeySeedRepresentation)!)

        let keyCollection = JWTKeyCollection()
        await keyCollection.add(mldsa: key)

        let jwt = try await keyCollection.sign(Foo(bar: 42))
        let verified = try await keyCollection.verify(jwt, as: Foo.self)

        #expect(verified.bar == 42)
    }
}

let mldsa65PrivateKeySeedRepresentation =
    "70cefb9aed5b68e018b079da8284b9d5cad5499ed9c265ff73588005d85c225c"

let mldsa87PrivateKeySeedRepresentation =
    "19e9e5efe0c1549ddb1d72213636d16fe2faeb2428257004ae464094ca536a66"

extension Data {
    init?(fromHexEncodedString string: String) {
        func decodeNibble(u: UInt8) -> UInt8? {
            switch u {
            case 0x30...0x39: u - 0x30
            case 0x41...0x46: u - 0x41 + 10
            case 0x61...0x66: u - 0x61 + 10
            default: nil
            }
        }

        self.init(capacity: string.utf8.count / 2)

        var iter = string.utf8.makeIterator()
        while let c1 = iter.next() {
            guard
                let val1 = decodeNibble(u: c1),
                let c2 = iter.next(),
                let val2 = decodeNibble(u: c2)
            else { return nil }
            self.append(val1 << 4 + val2)
        }
    }
}
