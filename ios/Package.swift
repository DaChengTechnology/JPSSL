// swift-tools-version:5.9
//
// JPSsl — jpssl 密码学库的 Swift 包（iOS）
//
// 依赖预编译的 JPSslC.xcframework（见 ios/build-xcframework.sh）。
// 构建：先在 macOS 上运行
//   ./ios/build-xcframework.sh
// 生成 JPSsl.xcframework，再在本目录消费本包：
//   .package(path: "ios")
//
// 最低平台：iOS 13.0 / arm64（ARMv8）。

import PackageDescription

let package = Package(
    name: "JPSsl",
    platforms: [
        .iOS(.v13)
    ],
    products: [
        .library(name: "JPSsl", targets: ["JPSsl"])
    ],
    targets: [
        // 预编译二进制（设备 + 模拟器 arm64 静态库，含 extern "C" Swift 符号）
        .binaryTarget(
            name: "JPSslC",
            path: "JPSsl.xcframework"
        ),
        // 惯用 Swift 封装层（import JPSslC → JPSsl.*）
        .target(
            name: "JPSsl",
            dependencies: ["JPSslC"],
            path: "Sources/JPSsl"
        )
    ]
)
