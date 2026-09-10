// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "OhMyOSI",
    platforms: [.macOS(.v14)],
    products: [
        .executable(name: "OhMyOSI", targets: ["OhMyOSI"]),
    ],
    targets: [
        .executableTarget(
            name: "OhMyOSI",
            path: "Sources",
            resources: [.copy("../Resources/macbook-pro.usdz"), .copy("../Resources/macbook-hero.png")]
        ),
    ]
)
