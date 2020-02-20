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
        .library(name: "CVaporJWTBoringSSL", type: .static, targets: ["CVaporJWTBoringSSL"]),
        MANGLE_END */
    ],
    dependencies: [ ],
    targets: [
        .systemLibrary(
            name: "CJWTKitOpenSSL",
            pkgConfig: "openssl",
            providers: [
                .apt(["openssl libssl-dev"]),
                .brew(["openssl@1.1"])
            ]
        ),
        .target(name: "CVaporJWTBoringSSL"),
        .target(name: "CJWTKitCrypto", dependencies: ["CJWTKitOpenSSL"]),
        .target(name: "JWTKit", dependencies: ["CJWTKitCrypto", "CVaporJWTBoringSSL"]),
        .testTarget(name: "JWTKitTests", dependencies: ["JWTKit"]),
    ]
)
