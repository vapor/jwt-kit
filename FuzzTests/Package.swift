// swift-tools-version:6.3

import PackageDescription

let package = Package(
    name: "fuzz-tests",
    platforms: [
        .macOS(.v13)
    ],
    dependencies: [
        .package(path: "../")
    ],
    targets: [
        .testTarget(
            name: "FuzzTests",
            dependencies: [
                .product(name: "JWTKit", package: "jwt-kit")
            ],
            path: "FuzzTests"
        )
    ]
)
