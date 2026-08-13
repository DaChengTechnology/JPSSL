#!/usr/bin/env bash
#
# build-xcframework.sh — 构建 JPSslC.xcframework（iOS, arm64 真机 + arm64 模拟器）
#
# 前置：macOS + Xcode 15+（C++20 协程需要 Apple Clang 15+；CMake 3.20+；ninja）
#
# 产物：ios/JPSsl.xcframework
#   - arm64-apple-ios13.0（真机 iphoneos）
#   - arm64-apple-ios13.0-simulator（Apple Silicon 模拟器）
#
# 用法：
#   ./ios/build-xcframework.sh            # 全部
#   ./ios/build-xcframework.sh device     # 仅真机
#   ./ios/build-xcframework.sh simulator  # 仅模拟器
#
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
IOS_DIR="$ROOT/ios"
BUILD_DIR="$ROOT/build-ios"

IOS_DEPLOYMENT_TARGET="13.0"
ARCH="arm64"
FRAMEWORK_NAME="JPSslC"
OUTPUT_XCFRAMEWORK="$IOS_DIR/JPSsl.xcframework"

MODE="${1:-all}"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "错误：必须在本机 macOS（需 Xcode）上构建 iOS XCFramework" >&2
  exit 1
fi
if ! command -v xcrun >/dev/null 2>&1; then
  echo "错误：找不到 xcrun，请安装 Xcode Command Line Tools" >&2
  exit 1
fi

# ── 1. 用 CMake + 工具链构建静态库（真机 / 模拟器） ─────────────────
build_slice() {
  local sdk="$1" name="$2"
  local out="$BUILD_DIR/$name"
  local static_lib

  echo "==> 构建 $name ($sdk, ${ARCH}, iOS ${IOS_DEPLOYMENT_TARGET}+) =="
  cmake -S "$ROOT" -B "$out" -G Ninja \
    -DCMAKE_TOOLCHAIN_FILE="$ROOT/cmake/toolchains/ios-arm64.cmake" \
    -DIOS_SDK="$sdk" \
    -DCMAKE_BUILD_TYPE=Release \
    -DJP_ENABLE_NEON=ON \
    -DJP_ENABLE_BENCH=OFF \
    -DJP_ENABLE_OPENMP=OFF \
    -DJP_ENABLE_MUSA=OFF
  cmake --build "$out" -j

  static_lib="$out/libjpssl_cpu.a"
  if [[ ! -f "$static_lib" ]]; then
    echo "错误：未找到静态库 $static_lib" >&2
    exit 1
  fi
  echo "==> 静态库：$static_lib =="
}

# ── 2. 组装静态 framework 切片 ───────────────────────────────────────
assemble_framework() {
  local name="$1" static_lib="$2" out="$3"
  local fw="$out/$FRAMEWORK_NAME.framework"

  rm -rf "$fw"
  mkdir -p "$fw/Headers" "$fw/Modules"

  cp "$static_lib" "$fw/$FRAMEWORK_NAME"
  cp "$IOS_DIR/bridge/jpssl.h" "$fw/Headers/"
  cp "$IOS_DIR/bridge/module.modulemap" "$fw/Modules/"

  cat > "$fw/Info.plist" <<PLIST
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
	<key>CFBundleDevelopmentRegion</key><string>en</string>
	<key>CFBundleExecutable</key><string>${FRAMEWORK_NAME}</string>
	<key>CFBundleIdentifier</key><string>org.jpssl.${FRAMEWORK_NAME}</string>
	<key>CFBundleInfoDictionaryVersion</key><string>6.0</string>
	<key>CFBundleName</key><string>${FRAMEWORK_NAME}</string>
	<key>CFBundlePackageType</key><string>FMWK</string>
	<key>CFBundleShortVersionString</key><string>1.0.0</string>
	<key>CFBundleVersion</key><string>1</string>
	<key>MinimumOSVersion</key><string>${IOS_DEPLOYMENT_TARGET}</string>
</dict>
</plist>
PLIST
}

# ── 3. 合并为 XCFramework ────────────────────────────────────────────
create_xcframework() {
  rm -rf "$OUTPUT_XCFRAMEWORK"
  mkdir -p "$IOS_DIR"

  local args=()
  if [[ -d "$BUILD_DIR/device/$FRAMEWORK_NAME.framework" ]]; then
    args+=(-framework "$BUILD_DIR/device/$FRAMEWORK_NAME.framework")
  fi
  if [[ -d "$BUILD_DIR/simulator/$FRAMEWORK_NAME.framework" ]]; then
    args+=(-framework "$BUILD_DIR/simulator/$FRAMEWORK_NAME.framework")
  fi
  if [[ ${#args[@]} -eq 0 ]]; then
    echo "错误：没有可合并的 framework 切片" >&2
    exit 1
  fi

  xcodebuild -create-xcframework "${args[@]}" -output "$OUTPUT_XCFRAMEWORK"
  echo "==> XCFramework：$OUTPUT_XCFRAMEWORK =="
}

if [[ "$MODE" == "all" || "$MODE" == "device" ]]; then
  build_slice iphoneos device
  assemble_framework device "$BUILD_DIR/device/libjpssl_cpu.a" "$BUILD_DIR/device"
fi
if [[ "$MODE" == "all" || "$MODE" == "simulator" ]]; then
  build_slice iphonesimulator simulator
  assemble_framework simulator "$BUILD_DIR/simulator/libjpssl_cpu.a" "$BUILD_DIR/simulator"
fi

create_xcframework
echo "完成。在 iOS 工程中："
echo "  1) 添加 $OUTPUT_XCFRAMEWORK 到 Frameworks（或通过 Package.swift 引用 ios/Package.swift）"
echo "  2) Swift: import JPSsl（惯用 API）或 import JPSslC（底层 C 函数）"
