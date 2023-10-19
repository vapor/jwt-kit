// swift-tools-version:5.9
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
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "2.6.0" ..< "4.0.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.0.0"),
        .package(url: "https://github.com/attaswift/BigInt.git", from: "5.3.0"),
    ],
    targets: [
        .target(name: "JWTKit", dependencies: [
            .product(name: "Crypto", package: "swift-crypto"),
            .product(name: "_CryptoExtras", package: "swift-crypto"),
            .product(name: "X509", package: "swift-certificates"),
            .product(name: "BigInt", package: "BigInt"),
        ],
        swiftSettings: [
            .enableUpcomingFeature("ConciseMagicFile"),
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
