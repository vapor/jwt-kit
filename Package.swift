// swift-tools-version:5.1
import PackageDescription

let package = Package(
    name: "jwt-kit",
    platforms: [
        .macOS(.v10_14)
    ],
    products: [
        .library(name: "JWTKit", targets: ["JWTKit"]),
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
        .target(name: "CJWTKitCrypto", dependencies: ["CJWTKitOpenSSL"]),
        .target(name: "JWTKit", dependencies: ["CJWTKitCrypto"]),
        .testTarget(name: "JWTKitTests", dependencies: ["JWTKit"]),
    ]
)
