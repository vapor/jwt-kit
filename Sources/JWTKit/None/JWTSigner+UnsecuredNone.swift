import class Foundation.JSONEncoder
import class Foundation.JSONDecoder

extension JWTSigner {
    public static var unsecuredNone: JWTSigner { .unsecuredNone(jsonEncoder: nil, jsonDecoder: nil) }
    
    public static func unsecuredNone(jsonEncoder: (any JWTJSONEncoder)?, jsonDecoder: (any JWTJSONDecoder)?) -> JWTSigner {
        .init(algorithm: UnsecuredNoneSigner(), jsonEncoder: jsonEncoder, jsonDecoder: jsonDecoder)
    }

}
