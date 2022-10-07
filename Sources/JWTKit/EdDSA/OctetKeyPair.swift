import Foundation

enum OctetKeyPair {
    case `public`(Data)
    case `private`(Data)
    case `publicPrivate`(x: Data, d: Data)
    
    init(publicKey: Data?, privateKey: Data?) throws {
        switch (publicKey, privateKey) {
            case (.some(let publicKey), .some(let privateKey)):
                self = .publicPrivate(x: publicKey, d: privateKey)
                
            case (.some(let publicKey), .none):
                self = .public(publicKey)
                
            case (.none, .some(let privateKey)):
                self = .private(privateKey)
                
            case (.none, .none):
                throw EdDSAError.publicAndPrivateKeyMissing
        }
    }
    
    var publicKey: Data? {
        switch self {
            case .private:
                return nil
                
            case .public(let publicKey), .publicPrivate(let publicKey, _):
                return publicKey
        }
    }
    
    var privateKey: Data? {
        switch self {
            case .public:
                return nil
                
            case .private(let privateKey), .publicPrivate(_, let privateKey):
                return privateKey
        }
    }
}
