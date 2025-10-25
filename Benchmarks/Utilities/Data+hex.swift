#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

extension Data {
    package init?(fromHexEncodedString string: String) {
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
