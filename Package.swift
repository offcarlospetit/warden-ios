// swift-tools-version: 6.2
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "Warden",
    platforms: [.iOS(.v16)],
    products: [
        .library(name: "Warden", targets: ["Warden"]),
    ],
    targets: [
        .target(
            name: "Warden",
            path: "Sources/Warden"
        ),
        .testTarget(
            name: "WardenTests",
            dependencies: ["Warden"],
            path: "Tests/WardenTests"
        ),
    ]
)
