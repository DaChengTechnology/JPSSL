# ohos.cmake — HarmonyOS NEXT / OpenHarmony (鸿蒙) 交叉编译 toolchain
#
# 面向鸿蒙 7.0 及兼容版本（HarmonyOS NEXT / OpenHarmony）的应用 native 模块：
# OpenHarmony NDK 只面向 .so（应用 native 库），不提供可执行文件链接运行时，
# 因此本 toolchain 下只构建静态库 + 共享库（libjpssl_cpu.a / libjpssl_cpu.so），
# 测试 / 命令行工具 / 示例会自动跳过（见根 CMakeLists 的 JP_OHOS 守卫）。
#
# 依赖：HarmonyOS NDK（DevEco Studio 自带，或命令行下载的 SDK 的 native 目录），
# 其中须包含 build/cmake/ohos.toolchain.cmake 与 clang 工具链。
#
# NDK 路径按以下顺序查找：
#   1. -DOHOS_NDK_HOME=<native 目录>
#   2. 环境变量 $OHOS_NDK_HOME
#   3. 环境变量 $DEVECO_SDK_HOME（DevEco Studio，取最新版本目录下的 native/）
#
# 用法（Windows / Linux / macOS 宿主机均可）：
#   cmake -S . -B build-ohos \
#       -DCMAKE_TOOLCHAIN_FILE=cmake/toolchains/ohos.cmake \
#       -DOHOS_NDK_HOME="C:/Users/xxx/DevEcoStudioSDK/.../native" \
#       -DOHOS_ARCH=arm64-v8a \
#       -DCMAKE_BUILD_TYPE=Release
#   cmake --build build-ohos
#
# 变量：
#   OHOS_NDK_HOME  NDK 根目录（HarmonyOS NEXT SDK 的 native 目录）
#   OHOS_ARCH      目标 ABI：arm64-v8a(默认) | armeabi-v7a | x86_64
#   OHOS_STL       C++ 运行时：c++_shared(默认) | c++_static
#   OHOS_API       API 等级（默认 12）
#
# arm64-v8a 下 NEON/crypto 硬件加速全量启用（AES-GCM / ChaCha20 / SHA-1/2/3 /
# SM3 / SM4 等），运行时按 cpu_features 自动分派，低版本芯片安全回退标量实现。

# ── 定位 NDK ────────────────────────────────────────────────────────────
if(DEFINED OHOS_NDK_HOME)
    set(_JPSSL_OHOS_NDK "${OHOS_NDK_HOME}")
elseif(DEFINED ENV{OHOS_NDK_HOME})
    set(_JPSSL_OHOS_NDK "$ENV{OHOS_NDK_HOME}")
elseif(DEFINED ENV{DEVECO_SDK_HOME})
    # DevEco Studio SDK 根目录下有多个版本目录，每个版本目录内含 native/
    file(GLOB _JPSSL_OHOS_SDK_DIRS
        LIST_DIRECTORIES true "$ENV{DEVECO_SDK_HOME}/*/native")
    list(SORT _JPSSL_OHOS_SDK_DIRS)
    list(REVERSE _JPSSL_OHOS_SDK_DIRS)
    list(LENGTH _JPSSL_OHOS_SDK_DIRS _JPSSL_OHOS_SDK_COUNT)
    if(_JPSSL_OHOS_SDK_COUNT GREATER 0)
        list(GET _JPSSL_OHOS_SDK_DIRS 0 _JPSSL_OHOS_NDK)
    endif()
endif()

if(NOT DEFINED _JPSSL_OHOS_NDK OR NOT EXISTS "${_JPSSL_OHOS_NDK}/build/cmake/ohos.toolchain.cmake")
    message(FATAL_ERROR
        "未找到 HarmonyOS NDK（需要其中 build/cmake/ohos.toolchain.cmake）。\n"
        "请通过 -DOHOS_NDK_HOME=<HarmonyOS NEXT SDK native 目录> 指定，\n"
        "或设置环境变量 OHOS_NDK_HOME / DEVECO_SDK_HOME（DevEco Studio SDK）。")
endif()

message(STATUS "HarmonyOS NDK: ${_JPSSL_OHOS_NDK}")

# ── 目标系统（CMakeLists 依据 CMAKE_SYSTEM_NAME STREQUAL "OHOS" 判定）──
set(CMAKE_SYSTEM_NAME OHOS)
set(CMAKE_SYSTEM_VERSION 1)

# ── 透传选项给 NDK 官方 toolchain ───────────────────────────────────────
set(OHOS_ARCH "arm64-v8a" CACHE STRING "OHOS target ABI: arm64-v8a | armeabi-v7a | x86_64")
set(OHOS_STL "c++_shared" CACHE STRING "OHOS C++ runtime: c++_shared | c++_static")
set(OHOS_API "12" CACHE STRING "OHOS API level")

# 归一化 CMAKE_SYSTEM_PROCESSOR（NDK toolchain 未设置时按 OHOS_ARCH 推断，
# 保证根 CMakeLists 的 aarch64/x86_64 匹配分支生效）
if(OHOS_ARCH STREQUAL "arm64-v8a")
    set(CMAKE_SYSTEM_PROCESSOR aarch64)
elseif(OHOS_ARCH STREQUAL "armeabi-v7a")
    set(CMAKE_SYSTEM_PROCESSOR armv7-a)
elseif(OHOS_ARCH STREQUAL "x86_64")
    set(CMAKE_SYSTEM_PROCESSOR x86_64)
endif()

# 引入 NDK 官方 toolchain（设置 clang/clang++、sysroot、目标三元组、链接参数等）
include("${_JPSSL_OHOS_NDK}/build/cmake/ohos.toolchain.cmake")
