// swift-tools-version:5.9
import PackageDescription

let package = Package(
    name: "VerifyBlind",
    platforms: [
        .iOS(.v13),
        // macOS yalnızca CI/geliştiricinin `swift test` ile kripto/mantık testlerini
        // simülatörsüz koşabilmesi için. iOS'a özgü (UIKit) yol `#if canImport(UIKit)`
        // ile korunur; SDK'nın asıl hedefi iOS'tur.
        .macOS(.v10_15)
    ],
    products: [
        .library(
            name: "VerifyBlind",
            targets: ["VerifyBlind"]
        )
    ],
    targets: [
        .target(
            name: "VerifyBlind",
            path: "Sources/VerifyBlind"
        ),
        .testTarget(
            name: "VerifyBlindTests",
            dependencies: ["VerifyBlind"],
            path: "Tests/VerifyBlindTests"
        )
    ]
)
