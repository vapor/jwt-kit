#if swift(>=5.8)

@_documentation(visibility: internal) @_exported import struct Foundation.Date
@_documentation(visibility: internal) @_exported import protocol Foundation.DataProtocol
@_documentation(visibility: internal) @_exported import protocol Foundation.ContiguousBytes

#else

@_exported import struct Foundation.Date
@_exported import protocol Foundation.DataProtocol
@_exported import protocol Foundation.ContiguousBytes

#endif