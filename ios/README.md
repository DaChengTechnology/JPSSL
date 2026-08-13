# iOS / Swift 集成（最低 iOS 13.0 · arm64 / ARMv8）

jpssl 的 iOS 支持：**CMake 交叉编译工具链** + **extern "C" Swift 符号桥接层** +
**XCFramework 打包** + **Swift Package**，全 API 面（哈希、AEAD、X25519/Ed25519、
ECDSA、SM2/SM3/SM4、RSA、X.509、TLS 1.3、Base64）。

## 目录结构

```
ios/
├── Package.swift                 # Swift Package（binaryTarget 引用 JPSsl.xcframework）
├── build-xcframework.sh          # macOS 构建脚本：真机 + 模拟器 → JPSsl.xcframework
├── Sources/JPSsl/JPSsl.swift     # 惯用 Swift API（JPSsl.Hash / AES / RSA / TLS 等）
├── bridge/
│   ├── jpssl.h                   # 纯 C 桥接头（Swift 符号声明）
│   ├── jpssl_bridge.cpp          # extern "C" 实现（iOS 构建时编入静态库）
│   └── module.modulemap          # Clang 模块 JPSslC
└── JPSsl.xcframework/            # 构建产物（gitignore，脚本生成）
```

## 需求

- macOS + Xcode **15+**（`tls_socket.hpp` 使用 C++20 协程，需 Apple Clang 15+）
- CMake ≥ 3.20、Ninja

## 构建

```bash
# 在 macOS 上执行
./ios/build-xcframework.sh
```

脚本会：
1. 用 `cmake/toolchains/ios-arm64.cmake` 分别构建
   `arm64-apple-ios13.0`（真机）与 `arm64-apple-ios13.0-simulator`（模拟器）
   两个静态库（工具链锁定 **arm64 / ARMv8**，最低 iOS 13.0；
   NEON 源按 `-march=armv8-a+crypto`，SHA-512/SHA-3/SM3/SM4 扩展源 armv8.4-a
   + 运行时 `cpu_features` 分派，低版本芯片安全回退标量）；
2. 组装 `JPSslC.framework`（Headers/jpssl.h + Modules/module.modulemap）；
3. `xcodebuild -create-xcframework` 合并为 `ios/JPSsl.xcframework`。

> 只构建单个切片：`./ios/build-xcframework.sh device` / `... simulator`

## 在 iOS 工程中使用

### 方式 A：Swift Package

```swift
dependencies: [.package(path: "ios")]
// 或本地/远程 git 依赖指向仓库 ios/ 目录
```

```swift
import JPSsl

let digest = JPSsl.Hash.SHA256.hash([0x61, 0x62, 0x63])
let (pub, priv) = JPSsl.Ed25519.keyPair()
let sig = JPSsl.Ed25519.sign(privateKey: priv, message: data)
let ok = JPSsl.Ed25519.verify(publicKey: pub, message: data, signature: sig)

let enc = JPSsl.ChaCha20.encrypt(key: key, nonce: nonce, plaintext: data)
```

### 方式 B：直接链接 XCFramework

把 `JPSsl.xcframework` 拖入 Xcode 工程 Frameworks，然后：

```swift
import JPSslC        // 底层 C 符号
import JPSsl         // 惯用 Swift API
```

## 架构说明

- **最低版本卡 armv8**：工具链 `CMAKE_SYSTEM_PROCESSOR=arm64`（ARMv8 64 位）、
  `CMAKE_OSX_ARCHITECTURES=arm64`、`CMAKE_OSX_DEPLOYMENT_TARGET=13.0`
  （iOS 13 起仅支持 64 位设备，天然 ≥ ARMv8）。不包含 armv7 / x86_64 slice。
- **Swift 符号导出**：`ios/bridge/jpssl.h` 全部为 `extern "C"` 纯 C 声明，
  由 `module.modulemap` 暴露为 Clang 模块 `JPSslC`，Swift `import` 后可直接调用，
  无需 `@_cdecl` / ObjC 桥。库内所有函数以固定字节缓冲区交换数据，
  变长输出由 `jp_free()` 释放。
- **NEON 硬件加速**：aarch64 下 AES-GCM / ChaCha20 / SHA-1 / SHA-256 /
  SHA-512 / SHA-3 / SM3 / SM4 自动分派；`ecp_nistz256_arm.S` 已含
  Mach-O/Apple 汇编兼容处理。
- **TLS**：`JPSsl.TLSConnection` 封装 `tls_connection`（TCP + TLS 1.3 客户端握手、
  系统信任库验证证书链、send/recv）。

## 已知限制

- 客户端 TLS 握手按系统信任库验证（iOS 无文件系统 CA bundle，
  `tls_trust_store::from_system()` 可能为空 → 握手可能失败；可后续扩展
  传入自定义信任库的桥接入口）。
- RSA 4096 的 OAEP / PKCS1v15 与 RSA 2048 的 4096 变体未在库中提供，桥接层
  不导出对应符号（PSS 2048/4096、OAEP 2048 已导出）。
- OpenMP 并行（CPU 批量 RSA 解密）在 iOS 上默认关闭。
