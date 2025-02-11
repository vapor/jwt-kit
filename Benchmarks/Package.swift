// swift-tools-version:5.9

import PackageDescription

let package = Package(
    name: "benchmarks",
    platforms: [
        .macOS(.v13)
    ],
    dependencies: [
        .package(path: "../"),
        .package(url: "https://github.com/ordo-one/package-benchmark.git", from: "1.22.0"),
    ],
    targets: [
        .executableTarget(
            name: "Signing",
            dependencies: [
                .product(name: "Benchmark", package: "package-benchmark"),
                .product(name: "JWTKit", package: "jwt-kit"),
            ],
            path: "Signing",
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "package-benchmark")
            ]
        ),
        .executableTarget(
            name: "Verifying",
            dependencies: [
                .product(name: "Benchmark", package: "package-benchmark"),
                .product(name: "JWTKit", package: "jwt-kit"),
            ],
            path: "Verifying",
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "package-benchmark")
            ]
        ),
        .executableTarget(
            name: "TokenLifecycle",
            dependencies: [
                .product(name: "Benchmark", package: "package-benchmark"),
                .product(name: "JWTKit", package: "jwt-kit"),
            ],
            path: "TokenLifecycle",
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "package-benchmark")
            ]
        ),
    ]
)
