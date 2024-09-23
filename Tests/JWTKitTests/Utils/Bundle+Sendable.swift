import Foundation

#if compiler(<6.0) && !canImport(Darwin)
extension Foundation.Bundle: @unchecked Swift.Sendable {}
#endif
