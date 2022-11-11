import Foundation

// https://www.rfc-editor.org/rfc/rfc8037.html#appendix-A
enum OctetKeyPair {
    case `public`(x: Data)
    case `private`(x: Data, d: Data)
    
    init(x: Data, d: Data) throws {
        self = .`private`(x: x, d: d)
    }
    
    init(x: Data) throws {
        self = .`public`(x: x)
    }
    
    var publicKey: Data {
        switch self {
            case .`public`(let x), .`private`(let x, _):
                return x
        }
    }
    
    var privateKey: Data? {
        switch self {
            case .`private`(_ , let d):
                return d
                
            case .`public`:
                return nil
        }
    }
}
