// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "SecuritySDK",
    platforms: [
        .iOS(.v15),
        .macOS(.v13),
    ],
    products: [
        .library(name: "SecuritySDK", targets: ["SecuritySDK"]),
    ],
    targets: [
        .target(
            name: "SecuritySDK",
            path: "ios-sdk/Sources/SecuritySDK"   // ✅ CORRECT
        ),
        .testTarget(
            name: "SecuritySDKTests",
            dependencies: ["SecuritySDK"],
            path: "ios-sdk/Tests/SecuritySDKTests"   // ✅ CORRECT
        ),
    ]
)