// swift-tools-version:5.6
import PackageDescription

let package = Package(
    name: "jwt-kit",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v6),
    ],
    products: [
        .library(name: "JWTKit", targets: ["JWTKit"]),
        /* This target is used only for symbol mangling. It's added and removed automatically because it emits build warnings. MANGLE_START
            .library(name: "CJWTKitBoringSSL", type: .static, targets: ["CJWTKitBoringSSL"]),
            MANGLE_END */
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "2.6.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", exact: "0.6.0"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0"),
    ],
    targets: [
        .target(name: "CJWTKitBoringSSL"),
        .target(name: "JWTKit", dependencies: [
            .target(name: "CJWTKitBoringSSL"),
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "_CryptoExtras", package: "swift-crypto"),
            .product(name: "X509", package: "swift-certificates"),
            .product(name: "BigInt", package: "BigInt"),
        ]),
        .testTarget(
            name: "JWTKitTests",
            dependencies: [
                "JWTKit",
            ],
            resources: [
                .copy("TestVectors"),
            ]
        ),
    ],
    cxxLanguageStandard: .cxx11
)
