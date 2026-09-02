// swift-tools-version:6.2
import PackageDescription

let package = Package(
    name: "jwt-kit",
    platforms: [
        .macOS(.v13),
        .iOS(.v15),
        .tvOS(.v15),
        .watchOS(.v8),
    ],
    products: [
        .library(name: "JWTKit", targets: ["JWTKit"])
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "4.1.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.15.0"),
        .package(url: "https://github.com/apple/swift-log.git", from: "1.0.0"),
    ],
    targets: [
        .target(
            name: "JWTKit",
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "CryptoExtras", package: "swift-crypto"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "Logging", package: "swift-log"),
            ],
            swiftSettings: swiftSettings
        ),
        .testTarget(
            name: "JWTKitTests",
            dependencies: [
                .target(name: "JWTKit")
            ],
            swiftSettings: swiftSettings
        ),
    ]
)

var swiftSettings: [SwiftSetting] {
    [
        // Re-enable this on all platforms once we drop iOS 15, where JSONEn/Decoder are not Sendable
        .treatAllWarnings(as: .error, .when(platforms: [.macOS, .linux, .windows, .android, .wasi, .openbsd])),
        .strictMemorySafety(),
        .enableUpcomingFeature("ExistentialAny"),
        .enableUpcomingFeature("InternalImportsByDefault"),
        .enableUpcomingFeature("MemberImportVisibility"),
        .enableUpcomingFeature("InferIsolatedConformances"),
        // .enableUpcomingFeature("NonisolatedNonsendingByDefault"),
        .enableUpcomingFeature("ImmutableWeakCaptures"),
        .enableExperimentalFeature("SuppressedAssociatedTypesWithDefaults"),
        .enableExperimentalFeature("LifetimeDependence"),
        .enableExperimentalFeature("Lifetimes"),
        .enableUpcomingFeature("LifetimeDependence"),
    ]
}
