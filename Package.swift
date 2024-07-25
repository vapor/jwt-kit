// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "jwt-kit",
    platforms: [
        .macOS(.v13),
        .iOS(.v16),
        .tvOS(.v16),
        .watchOS(.v9),
    ],
    products: [
        .library(name: "JWTKit", targets: ["JWTKit"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", branch: "main"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.2.0"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "JWTKit",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "BigInt", package: "BigInt"),
                .product(name: "Logging", package: "swift-log"),
            ]
        ),
        .testTarget(
            name: "JWTKitTests",
            dependencies: [
                "JWTKit",
            ],
            resources: [
                .copy("TestVectors"),
                .copy("TestCertificates"),
            ]
        ),
    ],
    swiftLanguageVersions: [.v6]
)
