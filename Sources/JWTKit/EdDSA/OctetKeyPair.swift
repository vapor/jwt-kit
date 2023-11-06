import Foundation

// https://www.rfc-editor.org/rfc/rfc8037.html#appendix-A
enum OctetKeyPair: Sendable {
    case `public`(x: Data)
    case `private`(x: Data, d: Data)

    init(x: Data, d: Data) throws {
        self = .private(x: x, d: d)
    }

    init(x: Data) throws {
        self = .public(x: x)
    }

    var publicKey: Data {
        switch self {
        case let .public(x), let .private(x, _):
            return x
        }
    }

    var privateKey: Data? {
        switch self {
        case let .private(_, d):
            return d

        case .public:
            return nil
        }
    }
}
