#!/usr/bin/env bash
#
# build.sh — 构建 macOS arm64 共享库 + 动态 framework（JPSslC.framework）
#
# 产物：
#   build-macos/libjpssl_cpu.dylib   (标准 macOS 动态库)
#   build-macos/libjpssl_cpu.so      (Mach-O dylib 副本，便于 FFI/dlopen 按 .so 约定加载)
#   build-macos/libjpssl_cpu.a       (静态库)
#   macos/JPSslC.framework           (动态 framework：JPSslC 二进制 + Headers + Modules + Info.plist)
#
# 用法：
#   ./macos/build.sh
#
set -euo pipefail

cd "$(dirname "$0")/.."
ROOT="$PWD"
IOS_DIR="$ROOT/ios"
MACOS_DIR="$ROOT/macos"
BUILD_DIR="$ROOT/build-macos"

ARCH="arm64"
DEPLOYMENT_TARGET="12.0"
FRAMEWORK_NAME="JPSslC"
FRAMEWORK_OUT="$MACOS_DIR/$FRAMEWORK_NAME.framework"

if [[ "$(uname -s)" != "Darwin" ]]; then
  echo "错误：必须在 macOS（Xcode Command Line Tools）上构建" >&2
  exit 1
fi
if ! command -v xcrun >/dev/null 2>&1; then
  echo "错误：找不到 xcrun，请安装 Xcode Command Line Tools" >&2
  exit 1
fi

echo "==> 配置（${ARCH}, macOS ${DEPLOYMENT_TARGET}+, Release）=="
cmake -S "$ROOT" -B "$BUILD_DIR" -G Ninja \
  -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_OSX_ARCHITECTURES="${ARCH}" \
  -DCMAKE_OSX_DEPLOYMENT_TARGET="${DEPLOYMENT_TARGET}" \
  -DJP_ENABLE_NEON=ON \
  -DJP_ENABLE_BENCH=OFF \
  -DJP_ENABLE_OPENMP=OFF \
  -DJP_ENABLE_MUSA=OFF
cmake --build "$BUILD_DIR" -j

DYLIB="$BUILD_DIR/libjpssl_cpu.dylib"
if [[ ! -f "$DYLIB" ]]; then
  echo "错误：未找到动态库 $DYLIB" >&2
  exit 1
fi
cp "$DYLIB" "$BUILD_DIR/libjpssl_cpu.so"
echo "==> 动态库：libjpssl_cpu.dylib / libjpssl_cpu.so =="

echo "==> 组装 ${FRAMEWORK_NAME}.framework（动态）=="
rm -rf "$FRAMEWORK_OUT"
mkdir -p "$FRAMEWORK_OUT/Headers" "$FRAMEWORK_OUT/Modules"

cp "$DYLIB" "$FRAMEWORK_OUT/$FRAMEWORK_NAME"
cp "$IOS_DIR/bridge/jpssl.h" "$FRAMEWORK_OUT/Headers/"
cp "$IOS_DIR/bridge/module.modulemap" "$FRAMEWORK_OUT/Modules/"

# framework 内二进制的 install name 指向 @rpath/JPSslC.framework/JPSslC
install_name_tool -id "@rpath/${FRAMEWORK_NAME}.framework/${FRAMEWORK_NAME}" \
  "$FRAMEWORK_OUT/$FRAMEWORK_NAME"

cat > "$FRAMEWORK_OUT/Info.plist" <<PLIST
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
	<key>LSMinimumSystemVersion</key><string>${DEPLOYMENT_TARGET}</string>
</dict>
</plist>
PLIST

# ad-hoc 签名，保证 codesign --verify 通过（本地开发可直接使用）
codesign --force --sign - "$FRAMEWORK_OUT"

echo "完成："
echo "  $BUILD_DIR/libjpssl_cpu.dylib / libjpssl_cpu.so / libjpssl_cpu.a"
echo "  $FRAMEWORK_OUT"
