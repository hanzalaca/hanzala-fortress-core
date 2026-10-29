// swift-tools-version: 5.9
import PackageDescription

// The HANZALA FORTRESS vault core: the v2 vault format, its cryptography and
// storage engine. App screens live in a separate, private project.
let package = Package(
    name: "HanzalaFortressCore",
    platforms: [.macOS(.v13), .iOS(.v16)],
    products: [
        .library(name: "HanzalaomatorCore", targets: ["HanzalaomatorCore"])
    ],
    dependencies: [
        .package(url: "https://github.com/jedisct1/swift-sodium.git", exact: "0.11.0")
    ],
    targets: [
        .target(
            name: "HanzalaomatorCore",
            dependencies: [
                .product(name: "Sodium", package: "swift-sodium")
            ],
            path: "Sources/HanzalaomatorCore"
        ),
        .testTarget(
            name: "HanzalaomatorCoreTests",
            dependencies: ["HanzalaomatorCore"],
            path: "Tests/HanzalaomatorCoreTests",
            resources: [.copy("Fixtures")]
        )
    ]
)
