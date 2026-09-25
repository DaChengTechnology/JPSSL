# 平台构建（iOS / macOS / Android / HarmonyOS）

除 Linux / Windows 的常规 CMake 构建外，仓库为移动端与桌面端提供一键构建脚本与
固定产物，且每个平台都有 GitHub Actions 工作流守护（见 [测试与 CI](Testing)）。

## iOS（XCFramework，arm64）

前置：macOS + Xcode 15+（C++20 协程需要 Apple Clang 15+）、CMake 3.20+、Ninja。

```bash
./ios/build-xcframework.sh            # 全部（真机 + 模拟器）
./ios/build-xcframework.sh device     # 仅真机
./ios/build-xcframework.sh simulator  # 仅模拟器
```

产物：`ios/JPSsl.xcframework`（`JPSslC.framework` 静态片，含 `Headers/jpssl.h`、
`Modules/module.modulemap` 与 `Info.plist`）。Swift 侧可 `import JPSslC` 使用
extern-C 桥接 API，或通过 `ios/Package.swift` 引入封装层 `JPSsl`。
最低部署版本 iOS 13.0 / arm64。

## macOS（arm64：动态库 + framework）

前置：macOS + Xcode Command Line Tools、CMake、Ninja（Apple Silicon 或 x64 均可，
`-DCMAKE_OSX_ARCHITECTURES=arm64` 固定目标切片）。

```bash
./macos/build.sh
```

产物：

- `build-macos/libjpssl_cpu.dylib` —— 标准 macOS 动态库
- `build-macos/libjpssl_cpu.so` —— Mach-O dylib 的同名副本，便于 FFI / `dlopen` 按 `.so` 约定加载
- `build-macos/libjpssl_cpu.a` —— 静态库
- `macos/JPSslC.framework` —— 动态 framework（`@rpath` install name、`Headers`/`Modules`/`Info.plist`、ad-hoc 签名）

链接示例：

```bash
clang app.c -Iios/bridge -Fmacos -framework JPSslC -o app
# 或直接链接动态库
clang app.c -Iios/bridge -Lbuild-macos -ljpssl_cpu -o app
```

## Android（AAR，arm64-v8a）

`android/` 为 Gradle 工程（AGP 8.2.2 / Kotlin 1.9.22 / NDK r26b，仅 arm64-v8a，C++20）。
构建需要 JDK 17 + Android SDK（platform 34 / build-tools 34 / NDK 26.1.10909125）。

```bash
gradle -p android assembleRelease
```

产物：`android/jpssl/build/outputs/aar/jpssl-release.aar`，内含
`jni/arm64-v8a/libjpssl.so` 与 `libc++_shared.so`。
Java / Kotlin API 见 `io.github.jpssl`（`Jpssl.java` / `Jpssl.kt`）。

## HarmonyOS / OpenHarmony（arm64-v8a .a / .so）

前置：OpenHarmony SDK 的 `native` 目录（含 `build/cmake/ohos.toolchain.cmake`，
例如 DevEco Studio SDK）。

```bash
export OHOS_NDK_HOME=<sdk>/.../native
cmake -S . -B build-ohos -G Ninja \
      -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/ohos.cmake \
      -DOHOS_ARCH=arm64-v8a -DCMAKE_BUILD_TYPE=Release
cmake --build build-ohos
```

产物：`build-ohos/libjpssl_cpu.a` 与 `libjpssl_cpu.so`（OpenHarmony NDK 不提供
可执行文件链接，测试 / CLI 自动跳过）。支持
`OHOS_ARCH=arm64-v8a | armeabi-v7a | x86_64`、`OHOS_STL=c++_shared | c++_static`、
`OHOS_API`（默认 12）。
