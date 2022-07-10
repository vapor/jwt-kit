// swift-tools-version:5.4
import PackageDescription

let package = Package(
    name: "jwt-kit",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .tvOS(.v13),
        .watchOS(.v6)
    ],
    products: [
        .library(name: "JWTKit", targets: ["JWTKit"]),
        /* This target is used only for symbol mangling. It's added and removed automatically because it emits build warnings. MANGLE_START
        .library(name: "CJWTKitBoringSSL", type: .static, targets: ["CJWTKitBoringSSL"]),
        MANGLE_END */
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", "1.0.0" ..< "3.0.0"),
		.package(url: "https://github.com/tsolomko/SWCompression.git", from: "4.7.0")
    ],
    targets: [
        .target(name: "CJWTKitBoringSSL"),
        .target(name: "JWTKit", dependencies: [
            .target(name: "CJWTKitBoringSSL"),
            .product(name: "Crypto", package: "swift-crypto"),
			.product(name: "SWCompression", package: "SWCompression")
        ]),
        .testTarget(name: "JWTKitTests", dependencies: [
            .target(name: "JWTKit"),
        ]),
    ],
     cxxLanguageStandard: .cxx11
)
