// swift-tools-version:5.6
import PackageDescription

// This package contains a vendored copy of BoringSSL. For ease of tracking
// down problems with the copy of BoringSSL in use, we include a copy of the
// commit hash of the revision of BoringSSL included in the given release.
// This is also reproduced in a file called hash.txt in the
// Sources/CCryptoBoringSSL directory. The source repository is at
// https://boringssl.googlesource.com/boringssl.
//
// BoringSSL Commit: 7a813621dac6878ab53b6ed7392939a8982226e8

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
        .package(url: "https://github.com/apple/swift-crypto.git", "2.0.0" ..< "4.0.0")
    ],
    targets: [
        .target(name: "CJWTKitBoringSSL"),
        .target(name: "JWTKit", dependencies: [
            .target(name: "CJWTKitBoringSSL"),
            .product(name: "Crypto", package: "swift-crypto"),
        ]),
        .testTarget(name: "JWTKitTests", dependencies: [
            .target(name: "JWTKit"),
        ]),
    ],
     cxxLanguageStandard: .cxx11
)
