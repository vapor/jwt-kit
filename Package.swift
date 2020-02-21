// swift-tools-version:5.1
import PackageDescription

let package = Package(
    name: "jwt-kit",
    platforms: [
        .macOS(.v10_14)
    ],
    products: [
        .library(name: "JWTKit", targets: ["JWTKit"]),
        /* This target is used only for symbol mangling. It's added and removed automatically because it emits build warnings. MANGLE_START
        .library(name: "CJWTKitBoringSSL", type: .static, targets: ["CJWTKitBoringSSL"]),
        MANGLE_END */
    ],
    dependencies: [ ],
    targets: [
        .target(name: "CJWTKitBoringSSL"),
        .target(name: "JWTKit", dependencies: ["CJWTKitBoringSSL"]),
        .testTarget(name: "JWTKitTests", dependencies: ["JWTKit"]),
    ]
)
